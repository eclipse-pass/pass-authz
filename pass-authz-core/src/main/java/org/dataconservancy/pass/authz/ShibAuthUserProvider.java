/*
 * Copyright 2017 Johns Hopkins University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.dataconservancy.pass.authz;

import static java.util.Arrays.stream;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toSet;
import static org.dataconservancy.pass.authz.ConfigUtil.getValue;

import java.net.URI;
import java.time.Duration;
import java.util.Enumeration;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the AuthUserProvider interface for JHU's Shibboleth service We are interested in four headers:
 * <ul>
 * <li>Displayname - First Last</li>
 * <li>Mail - the user's preferred email address</li>
 * <li>Eppn - the user's "official" JHU email address, which starts with the users institutional id</li>
 * <li>Unscoped-Affiliations - a semi-colon-separated list of roles or statuses indicating employment type</li>
 * <li>Employeenumber - the user's employee id, durable across institutional id changes</li>
 * </ul>
 *
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
public class ShibAuthUserProvider implements AuthUserProvider {

    public static final String CONFIG_SHIB_USE_HEADERS = "authz.shib.use.headers";

    Logger LOG = LoggerFactory.getLogger(ShibAuthUserProvider.class);

    public static final String DISPLAY_NAME_HEADER = "Displayname";

    public static final String EMAIL_HEADER = "Mail";

    public static final String EPPN_HEADER = "Eppn";

    public static final String UNSCOPED_AFFILIATION_HEADER = "Unscoped-Affiliation";

    public static final String SCOPED_AFFILIATION_HEADER = "Affiliation";

    public static final String EMPLOYEE_ID = "Employeenumber";

    static final String FACULTY_AFFILIATION = "FACULTY";

    final PassClient passClient;

    final ExpiringLRUCache<String, URI> userCache;

    boolean useShibHeaders = ofNullable(getValue(CONFIG_SHIB_USE_HEADERS)).map(Boolean::valueOf).orElse(false);

    boolean isFaculty = false;

    public ShibAuthUserProvider(PassClient client) {
        this.passClient = client;
        userCache = new ExpiringLRUCache<>(100, Duration.ofMinutes(10));
    }

    public ShibAuthUserProvider(PassClient client, ExpiringLRUCache<String, URI> cache) {
        this.passClient = client;
        userCache = cache;
    }

    @Override
    public AuthUser getUser(HttpServletRequest request) {
        return getUser(request, (u) -> u);
    }

    /**
     * This method reads the shib headers and uses the values to populate an {@link AuthUser} object, which is
     * consumed by the {@code UserServlet} to build a {@code User} object for the back-end storage system.
     *
     * @param request the HTTP servlet request
     * @return the populated AuthUser
     */
    @Override
    public AuthUser getUser(HttpServletRequest request, Function<AuthUser, AuthUser> doAfter) {

        boolean isFaculty = false;

        if (LOG.isDebugEnabled()) {

            LOG.debug("Request headers: ");
            final Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                final String name = headerNames.nextElement();
                LOG.debug("   " + name + ": " + request.getHeader(name));
            }
        }

        final String displayName = getShibAttr(request, DISPLAY_NAME_HEADER, String::trim);
        final String emailAddress = getShibAttr(request, EMAIL_HEADER, String::trim);
        final String institutionalId = getShibAttr(request, EPPN_HEADER, s -> s.split("@")[0]);
        final String employeeId = getShibAttr(request, EMPLOYEE_ID, e -> e);

        final String[] affiliationArray = getShibAttr(request, UNSCOPED_AFFILIATION_HEADER, s -> s.split(";"));

        if (affiliationArray != null) {
            for (final String affiliation : affiliationArray) {
                if (affiliation.trim().equalsIgnoreCase(FACULTY_AFFILIATION)) {
                    isFaculty = true;
                    break;
                }
            }
        }

        final AuthUser user = new AuthUser();
        user.setEmployeeId(employeeId);
        user.setName(displayName);
        user.setEmail(emailAddress);
        if (institutionalId != null) {
            user.setInstitutionalId(institutionalId.toLowerCase());// this is our normal format
        }
        user.setFaculty(isFaculty);
        user.setPrincipal(getShibAttr(request, EPPN_HEADER, s -> s));

        ofNullable(user.getPrincipal())
                .filter(s -> s.contains("@"))
                .map(s -> s.split("@")[1])
                .ifPresent(user.getDomains()::add);

        user.getDomains().addAll(stream(ofNullable(getShibAttr(request, SCOPED_AFFILIATION_HEADER, s -> s.split(";")))
                .orElse(new String[0]))
                        .filter(sa -> sa.contains("@"))
                        .map(sa -> sa.split("@")[1])
                        .collect(toSet()));

        if (employeeId != null) {
            LOG.debug("Looking up User based in employeeId '{}'", employeeId);
            try {
                final URI id = userCache.getOrDo(employeeId,
                        () -> {
                            user.setId(findUserId(employeeId));
                            final AuthUser filtered = doAfter.apply(user);
                            return filtered.getId();
                        });

                user.setId(id);
                LOG.debug("User resource for {} is {}", employeeId, id);
            } catch (final Exception e) {
                LOG.warn("Error looking up user with employee id " + employeeId,
                        e);
            }
        } else {
            LOG.debug("No shibboleth employee id; skipping user lookup ");
        }

        return user;
    }

    /**
     * Checks for User record by employeeId. This depends on the user being indexed, so will retry a number of times
     * before returning null to make sure there is time for indexing of a new user to happen. Note that RETRIES is set
     * to 5, this is based on current configuration of index refresh rate at 1 second
     *
     * @param employeeId
     * @return
     */
    private URI findUserId(String employeeId) {
        final int RETRIES = 1;
        for (int tries = 0; tries < RETRIES; tries++) {
            final URI userId = passClient.findByAttribute(User.class, "localKey", employeeId);
            if (userId != null) {
                return userId;
            } else if (tries + 1 < RETRIES) { // Don't bother delay on the final one
                try {
                    LOG.debug("Could not find User record for employee {}, waiting and trying again (try #{})",
                            employeeId, tries);
                    Thread.sleep(1000);
                } catch (final InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    LOG.warn("Thread was interrupted while waiting to retry employee {} lookup.", employeeId);
                }
            }
        }
        LOG.info("User with employee id {} was not found before timeout", employeeId);
        return null;
    }

    private <T> T getShibAttr(HttpServletRequest request, String name, Function<String, T> transform) {
        final T value = transform(ofNullable(request.getAttribute(name))
                .map(Object::toString)
                .orElse(useShibHeaders ? request.getHeader(name) : null), transform);

        LOG.debug("Shib attribute {} is {}", name, value);
        return value;
    }

    private <T> T transform(String value, Function<String, T> transform) {
        return ofNullable(value)
                .map(transform)
                .orElse(null);
    }
}

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
import java.util.Collection;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.User;
import org.dataconservancy.pass.model.support.Identifier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the AuthUserProvider interface for JHU's Shibboleth service We are interested in six headers
 * <ul>
 * <li>Displayname - First Last</li>
 * <li>Mail - the user's preferred email address</li>
 * <li>Eppn - the user's "official" JHU email address, which starts with the users institutional id</li>
 * <li>Affiliation - a semi-colon-separated list of roles or statuses indicating employment type and domain</li>
 * <li>Employeenumber - the user's employee id, durable across institutional id changes</li>
 * <li>unique-id - the user's hopkins id, durable across institutional id changes, for all active hopkins community
 * members</li>
 * </ul>
 *
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
public class ShibAuthUserProvider implements AuthUserProvider {

    /** Property for configuing whether to use shib headers (vs attributes) */
    public static final String CONFIG_SHIB_USE_HEADERS = "authz.shib.use.headers";

    public static final String CONFIG_SHIB_CACHE_LIFE = "authz.shib.cache.minutes";

    public static final String CONFIG_SHIB_CACHE_SIZE = "authz.shib.cache.size";

    Logger LOG = LoggerFactory.getLogger(ShibAuthUserProvider.class);

    /** Display name http header */
    public static final String DISPLAY_NAME_HEADER = "Displayname";

    /** Email http header */
    public static final String EMAIL_HEADER = "Mail";

    /** EPPN http header */
    public static final String EPPN_HEADER = "Eppn";

    /** Scoped affiliation http header */
    public static final String SCOPED_AFFILIATION_HEADER = "Affiliation";

    /** Employee number http header */
    public static final String EMPLOYEE_ID_HEADER = "Employeenumber";

    /** Unique ID header */
    public static final String HOPKINS_ID_HEADER = "unique-id";

    /** Employee ID Identifier type */
    public static final String EMPLOYEE_ID_TYPE = "employeeid";

    /** hopkins id identifier type */
    public static final String HOPKINS_ID_TYPE = "hopkinsid";

    /** JHED id type */
    public static final String JHED_ID_TYPE = "jhed";

    final PassClient passClient;

    final ExpiringLRUCache<String, AuthUser> userCache;

    boolean useShibHeaders = ofNullable(getValue(CONFIG_SHIB_USE_HEADERS)).map(Boolean::valueOf).orElse(false);

    /**
     * Constructor.
     *
     * @param client PASS client.
     */
    public ShibAuthUserProvider(PassClient client) {
        this.passClient = client;
        final int minutes = Integer.valueOf(ofNullable(getValue(CONFIG_SHIB_CACHE_LIFE)).orElse("10"));
        final int size = Integer.valueOf(ofNullable(getValue(CONFIG_SHIB_CACHE_SIZE)).orElse("100"));
        userCache = new ExpiringLRUCache<>(size, Duration.ofMinutes(minutes));
    }

    /**
     * Constructor.
     *
     * @param client PASS client
     * @param cache LRU cache.
     */
    public ShibAuthUserProvider(PassClient client, ExpiringLRUCache<String, AuthUser> cache) {
        this.passClient = client;
        userCache = cache;
    }

    /**
     * This method reads the shib headers and uses the values to populate an {@link AuthUser} object, which is
     * consumed by the {@code UserServlet} to build a {@code User} object for the back-end storage system.
     *
     * @param request the HTTP servlet request
     * @param doAfter a filter applied to the {@code AuthUser} by the caller
     * @param allowCached ignored by this implementation
     * @return the populated AuthUser
     */
    @Override
    public AuthUser getUser(HttpServletRequest request, Function<AuthUser, AuthUser> doAfter, boolean allowCached) {

        if (LOG.isDebugEnabled() && request != null) {

            LOG.debug("Request headers: ");
            final Enumeration<String> headerNames = request.getHeaderNames();
            if (headerNames != null) {
                while (headerNames.hasMoreElements()) {
                    final String name = headerNames.nextElement();
                    LOG.debug("   " + name + ": " + request.getHeader(name));
                }
            }
        }

        final String displayName = getShibAttr(request, DISPLAY_NAME_HEADER, String::trim);
        final String emailAddress = getShibAttr(request, EMAIL_HEADER, String::trim);
        final String domain = getShibAttr(request, EPPN_HEADER, s -> s.split("@")[1]);
        String institutionalId = getShibAttr(request, EPPN_HEADER, s -> s.split("@")[0]);
        if (institutionalId != null && !institutionalId.isEmpty()) {
            institutionalId = new Identifier(domain, JHED_ID_TYPE, institutionalId.toLowerCase()).serialize();
        }

        final String employeeId = new Identifier(domain, EMPLOYEE_ID_TYPE, getShibAttr(request, EMPLOYEE_ID_HEADER,
                e -> e)).serialize();
        final String hopkinsId = new Identifier(domain, HOPKINS_ID_TYPE, getShibAttr(request, HOPKINS_ID_HEADER,
                s -> s.split("@")[0])).serialize();

        String cacheLookupId = null;

        final AuthUser authUser = new AuthUser();
        authUser.setName(displayName);
        authUser.setEmail(emailAddress);
        // populate the locatorId list with durable ids first - shib user always has hopkins id
        if (hopkinsId != null) {
            authUser.getLocatorIds().add(hopkinsId);
            cacheLookupId = hopkinsId;
        }
        if (employeeId != null) {
            authUser.getLocatorIds().add(employeeId);
        }
        if (institutionalId != null) {
            authUser.getLocatorIds().add(institutionalId);
        }

        authUser.setPrincipal(getShibAttr(request, EPPN_HEADER, s -> s));

        ofNullable(authUser.getPrincipal())
                .filter(s -> s.contains("@"))
                .map(s -> s.split("@")[1])
                .ifPresent(authUser.getDomains()::add);

        authUser.getDomains().addAll(stream(ofNullable(getShibAttr(request, SCOPED_AFFILIATION_HEADER, s -> s.split(
                ";")))
                        .orElse(new String[0]))
                                .filter(sa -> sa.contains("@"))
                                .map(sa -> sa.split("@")[1])
                                .collect(toSet()));

        if (cacheLookupId != null) {
            LOG.debug("Looking up User based on hopkins id '{}'", cacheLookupId);
            try {

                final Callable<AuthUser> criticalSection = () -> {

                    // If a User resource exists in the index for the AuthUser, retrieve and set the backing User
                    // resource on the AuthUser.  Otherwise, return the AuthUser with no backing User resource.
                    // Either way, the returned AuthUser will be cached.

                    Optional<AuthUser> fromIndex = findUser(authUser.getLocatorIds())
                            .map(uri -> {
                                User user = passClient.readResource(uri, User.class);
                                authUser.setUser(user);
                                authUser.setId(user.getId());
                                return authUser;
                            });
                    return fromIndex.orElse(authUser);
                };

                // Retrieve the AuthUser from the cache, which may or may not have a backing User resource, and
                // return it to the caller.
                final AuthUser authUserFromCache = userCache.getOrDo(hopkinsId, criticalSection, doAfter);
                if (authUserFromCache != null) {
                    return authUserFromCache;
                }
                LOG.debug("User resource for {} is {}", hopkinsId, authUser.getId());
            } catch (final Exception e) {
                throw new RuntimeException("Error while looking up user by locatorIds" + authUser.getLocatorIds()
                        .toString(), e);
            }
        } else {
            LOG.debug("No shibboleth hopkins id; skipping user lookup ");
        }

        return authUser;
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

    private Optional<URI> findUser(Collection<String> locatorIds) {
        return locatorIds.stream()
                .map(locatorId -> passClient.findByAttribute(User.class, "locatorIds", locatorId))
                .filter(Objects::nonNull)
                .findAny();
    }
}

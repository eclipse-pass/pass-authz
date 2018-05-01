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

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.User;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.Duration;

import static java.util.Arrays.stream;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toSet;

/**
 * Implementation of the AuthUserProvider interface for JHU's Shibboleth service
 * We are interested in four headers:
 * <ul>
 *     <li>Displayname  - First Last</li>
 *     <li>Mail - the user's preferred email address</li>
 *     <li>Eppn - the user's "official" JHU email address, which starts with the users institutional id</li>
 *     <li>Unscoped-Affiliations - a semi-colon-separated list of roles or statuses indicating employment type </li>
 * </ul>
 *
 *
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
public class ShibAuthUserProvider implements AuthUserProvider {

    static final String DISPLAY_NAME_HEADER = "Displayname";
    static final String EMAIL_HEADER = "Mail";
    static final String EPPN_HEADER = "Eppn";
    static final String UNSCOPED_AFFILIATION_HEADER = "Unscoped-Affiliation";
    static final String SCOPED_AFFILIATION_HEADER = "Affiliation";
    
    final PassClient passClient;
    
    final ExpiringLRUCache<String, URI> userCache;
    
    public ShibAuthUserProvider(PassClient client) {
        this.passClient = client;
        userCache = new ExpiringLRUCache<>(100, Duration.ofMinutes(10));
    }
    
    public ShibAuthUserProvider(PassClient client, ExpiringLRUCache<String, URI> cache) {
        this.passClient = client;
        userCache = cache;
    }

    /**
     * This method reads the shib headers and uses the values to populate an {@link AuthUser} object, which is consumed
     * by the {@code UserServlet} to build a {@code User} object for the back-end storage system.
     * @param request the HTTP servlet request
     * @return the populated AuthUser
     */
    @Override
    public AuthUser getUser(HttpServletRequest request) {

        String facultyAffiliation = "FACULTY";

        String displayName;
        String emailAddress;
        String institutionalId;
        boolean isFaculty = false;

        displayName = request.getHeader(DISPLAY_NAME_HEADER).trim();
        emailAddress = request.getHeader(EMAIL_HEADER).trim();
        institutionalId = request.getHeader(EPPN_HEADER).split("@")[0];

        String[] affiliationArray = request.getHeader(UNSCOPED_AFFILIATION_HEADER).split(";");
        for (String affiliation : affiliationArray) {
            if (affiliation.trim().equalsIgnoreCase(facultyAffiliation)) {
                isFaculty = true;
                break;
            }
        }

        URI id = userCache.getOrDo(institutionalId, () -> passClient.findByAttribute(User.class, "institutionalId", institutionalId));

        final AuthUser user = new AuthUser();
        user.setName(displayName);
        user.setEmail(emailAddress);
        user.setInstitutionalId(institutionalId.trim().toLowerCase());//this is our normal format
        user.setFaculty(isFaculty);
        user.setId(id);
        user.setPrincipal(request.getHeader(EPPN_HEADER));
        
        
        user.getDomains().add(request.getHeader(EPPN_HEADER).split("@")[1]);
        user.getDomains().addAll(stream(ofNullable(
                request.getHeader(SCOPED_AFFILIATION_HEADER)).orElse("").split(";"))
                        .filter(sa -> sa.contains("@"))
                        .map(sa -> sa.split("@")[1])
                        .collect(toSet()));

        return user;
    }
}

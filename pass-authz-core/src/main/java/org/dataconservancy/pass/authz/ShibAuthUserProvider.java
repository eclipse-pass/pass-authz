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

import org.dataconservancy.pass.client.fedora.FedoraPassClient;
import org.dataconservancy.pass.model.User;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;

/**
 * Implementation of the AuthUserProvider interface for JHU's Shibboleth service
 * We are interested in four headers:
 * <ul>
 *     <li>Displayname  - First Last</li>
 *     <li>Mail - the user's preferred email address</li>
 *     <li>Eppn - the user's "official" JHU email address, which starts with the users institutional id</li>
 *     <li>Unscoped-Affiliations - a semi-colon-separated list of roles or statuses indicating employment type </li>
 *     <li>Employeenumber - the user's employee id, durable across institutional id changes</li>
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
    static final String EMPLOYEE_ID = "Employeenumber";

    /**
     * This method reads the shib headers and uses the values to populate an {@link AuthUser} object, which is consumed
     * by the {@code UserServlet} to build a {@code User} object for the back-end storage system.
     * @param request the HTTP servlet request
     * @return the populated AuthUser
     */
    @Override
    public AuthUser getUser(HttpServletRequest request) {

        FedoraPassClient passClient = new FedoraPassClient();

        String facultyAffiliation = "FACULTY";

        String displayName;
        String emailAddress;
        String institutionalId;
        String employeeId;
        boolean isFaculty = false;

        displayName = request.getHeader(DISPLAY_NAME_HEADER).trim();
        emailAddress = request.getHeader(EMAIL_HEADER).trim();
        institutionalId = request.getHeader(EPPN_HEADER).split("@")[0];
        employeeId = request.getHeader(EMPLOYEE_ID);

        String[] affiliationArray = request.getHeader(UNSCOPED_AFFILIATION_HEADER).split(";");
        for (String affiliation : affiliationArray) {
            if (affiliation.trim().equalsIgnoreCase(facultyAffiliation)) {
                isFaculty = true;
                break;
            }
        }

        URI id = passClient.findByAttribute(User.class, "localKey", employeeId);

        final AuthUser user = new AuthUser();
        user.setEmployeeId(employeeId);
        user.setName(displayName);
        user.setEmail(emailAddress);
        user.setInstitutionalId(institutionalId.toLowerCase());//this is our normal format
        user.setFaculty(isFaculty);
        user.setId(id);

        return user;
    }
}

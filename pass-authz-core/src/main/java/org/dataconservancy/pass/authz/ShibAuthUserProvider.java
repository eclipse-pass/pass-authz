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

import javax.servlet.http.HttpServletRequest;

/**
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
public class ShibAuthUserProvider implements AuthUserProvider {

    static final String DISPLAY_NAME_HEADER = "Displayname";
    static final String EMAIL_HEADER = "Mail";
    static final String EPPN_HEADER = "Eppn";
    static final String UNSCOPED_AFFILIATION_HEADER = "Unscoped-Affiliation";


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

        final AuthUser user = new AuthUser();
        user.setName(displayName);
        user.setEmail(emailAddress);
        user.setInstitutionalId(institutionalId.trim().toLowerCase());//this is our normal format
        user.setFaculty(isFaculty);

        return user;
    }
}

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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

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

        String displayName = "";
        String emailAddress = "";
        String institutionalId = "";
        boolean isFaculty = false;

        Map<String, String> headerMap = new HashMap<>();

        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            headerMap.put(key, value);
        }

        if (headerMap.keySet().contains(DISPLAY_NAME_HEADER)) {
            displayName = headerMap.get(DISPLAY_NAME_HEADER).trim();
        }
        if (headerMap.keySet().contains(EMAIL_HEADER)) {
            emailAddress = headerMap.get(EMAIL_HEADER).trim();
        }
        if (headerMap.keySet().contains(EPPN_HEADER)) {
            institutionalId = headerMap.get(EPPN_HEADER).split("@")[0];
        }
        if (headerMap.keySet().contains(UNSCOPED_AFFILIATION_HEADER)) {
            String[] affiliationArray = headerMap.get(UNSCOPED_AFFILIATION_HEADER).split(";");
            for (String affiliation : affiliationArray) {
                if (affiliation.trim().equalsIgnoreCase(facultyAffiliation)) {
                    isFaculty = true;
                    break;
                }
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

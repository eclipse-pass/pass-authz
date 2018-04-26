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

package org.dataconservancy.pass.authz.service.user;

import java.io.IOException;
import java.io.Writer;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;
import org.dataconservancy.pass.authz.ShibAuthUserProvider;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dataconservancy.pass.client.fedora.FedoraPassClient;
import org.dataconservancy.pass.model.User;

/**
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
@SuppressWarnings("serial")
public class UserServlet extends HttpServlet {

    ObjectMapper mapper = new ObjectMapper();

    AuthUserProvider provider = new ShibAuthUserProvider();

    FedoraPassClient fedoraClient = new FedoraPassClient();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");

        final AuthUser shibUser = provider.getUser(request);
        URI id = shibUser.getId();
        String email = shibUser.getEmail();
        String displayName = shibUser.getName();
        String institutionalId = shibUser.getInstitutionalId();

        User user = null;

        //does the user already exist in the repository?
        if (id != null) {
            user = fedoraClient.readResource(id, User.class);

            //is the user in COEUS? if not, update; else leave alone
            if (user.getLocalKey() == null ) {//not in COEUS
                boolean update = false;

                if(!user.getEmail().equals(email)) {
                    user.setEmail(email);
                    update=true;
                }
                if(!user.getDisplayName().equals(displayName)) {
                    user.setDisplayName(displayName);
                    update=true;
                }
                if(!user.getInstitutionalId().equals(institutionalId)) {
                    user.setInstitutionalId(institutionalId);
                    update=true;
                }

                if(update) {
                    fedoraClient.updateResource(user);
                }
            }

        } else {//no id, so we add new user to repository if eligible
            if (shibUser.isFaculty()) {
                user = new User();
                user.setInstitutionalId(institutionalId);
                user.setDisplayName(displayName);
                user.setEmail(email);
                user.getRoles().add(User.Role.SUBMITTER);
                id = fedoraClient.createResource(user);
            }
        }

        //at this point, any eligible person will have an up to date User object in Fedora
        //and the up to date User object and valid id here
        //if the person is not eligible, id and user will be null

        if (id != null) {
            try (Writer out = response.getWriter()) {
                mapper.writerWithDefaultPrettyPrinter().writeValue(out, user);
            }
        } else {
            //spike the intruder
        }
    }

}

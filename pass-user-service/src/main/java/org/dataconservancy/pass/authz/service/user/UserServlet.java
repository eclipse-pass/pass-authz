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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;
import org.dataconservancy.pass.authz.ShibAuthUserProvider;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This class gets an {@link AuthUser} object from the {@link ShibAuthUserProvider} and creates {@link User} to be
 * stored in the back end storage for PASS.
 *
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
@SuppressWarnings("serial")
public class UserServlet extends HttpServlet {

    Logger LOG = LoggerFactory.getLogger(UserServlet.class);

    ExecutorService updater = Executors.newCachedThreadPool();

    ObjectMapper mapper = new ObjectMapper().setSerializationInclusion(Include.NON_NULL);

    PassClient fedoraClient = PassClientFactory.getPassClient();

    AuthUserProvider provider = new ShibAuthUserProvider(fedoraClient);

    /**
     * A method which calls {@link ShibAuthUserProvider#getUser(HttpServletRequest)} to get an {@link AuthUser} in
     * order to populate a {@link User} object and create/update and store it
     *
     * @param request - the {@code HttpServletRequest}
     * @param response - the {@code HttpServletResponse}
     * @throws IOException - if the
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");

        final AuthUser shibUser = provider.getUser(request);
        URI id = shibUser.getId();

        final User user;

        // does the user already exist in the repository?
        if (id != null) {
            LOG.info("User {} found at {}", shibUser.getPrincipal(), id);
            user = fedoraClient.readResource(id, User.class);
            boolean update = false;

            // employeeId should never change
            // each user provider will only adjust fields for which it is authoritative
            // shib is authoritative for these

            if (user.getEmail() == null || !user.getEmail().equals(shibUser.getEmail())) {
                user.setEmail(shibUser.getEmail());
                update = true;
            }
            if (user.getDisplayName() == null || !user.getDisplayName().equals(shibUser.getName())) {
                user.setDisplayName(shibUser.getName());
                update = true;
            }
            if (user.getInstitutionalId() == null || !user.getInstitutionalId().equals(shibUser
                    .getInstitutionalId())) {
                user.setInstitutionalId(shibUser.getInstitutionalId());
                update = true;
            }

            if (update) {
                LOG.info("User record for {} in repository is out of date, updating {} ", shibUser.getPrincipal(),
                        user.getId());
                updater.execute(() -> fedoraClient.updateResource(user));
            }

        } else {// no id, so we add new user to repository if eligible
            if (shibUser.isFaculty()) {
                LOG.info("Creating new record for new user {}", shibUser.getPrincipal());
                user = new User();
                user.setLocalKey(shibUser.getEmployeeId());
                user.setInstitutionalId(shibUser.getInstitutionalId());
                user.setDisplayName(shibUser.getName());
                user.setEmail(shibUser.getEmail());
                user.getRoles().add(User.Role.SUBMITTER);
                id = fedoraClient.createResource(user);
            } else {
                LOG.warn("{} is not faculty, go away!", shibUser.getPrincipal());
                user = null;
            }
        }

        // at this point, any eligible person will have an up to date User object in Fedora
        // and the up to date User object and valid id here
        // if the person is not eligible, id and user will be null

        if (id != null && user != null) {
            try (Writer out = response.getWriter()) {
                mapper.writerWithDefaultPrettyPrinter().writeValue(out, user);
                response.setStatus(200);
            }
        } else {
            LOG.info("{} not authorized", shibUser.getPrincipal());
            response.setStatus(401);
        }
    }

}

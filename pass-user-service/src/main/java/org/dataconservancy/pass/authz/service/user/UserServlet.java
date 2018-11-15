/*
 * Copyright 2018 Johns Hopkins University
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
import java.io.OutputStream;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;
import org.dataconservancy.pass.authz.LogUtil;
import org.dataconservancy.pass.authz.ShibAuthUserProvider;
import org.dataconservancy.pass.authz.usertoken.BadTokenException;
import org.dataconservancy.pass.authz.usertoken.Token;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.client.PassJsonAdapter;
import org.dataconservancy.pass.client.adapter.PassJsonAdapterBasic;
import org.dataconservancy.pass.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class gets an {@link AuthUser} object from the {@link ShibAuthUserProvider} and creates {@link User} to be
 * stored in the back end storage for PASS.
 *
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
@SuppressWarnings("serial")
public class UserServlet extends HttpServlet {

    static final Logger LOG = LoggerFactory.getLogger(UserServlet.class);

    PassJsonAdapter json = new PassJsonAdapterBasic();

    PassClient fedoraClient = PassClientFactory.getPassClient();

    AuthUserProvider provider = new ShibAuthUserProvider(fedoraClient);

    TokenService tokenService = new TokenService();

    static {
        LogUtil.adjustLogLevels();
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        LOG.info("Publishing authUserProvider to servlet context");
        getServletContext().setAttribute("authUserProvider", provider);
    }

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

        LOG.debug("Servicing new request");

        final Token usertoken = tokenService.fromQueryString(request.getQueryString());

        final AuthUser shibUser;
        try {
            shibUser = provider.getUser(request, authUser -> {

                LOG.debug("Entering critical section");

                // If the AuthUser returned from the AuthUserProvider does not have a backing User resource, then
                // create one from Shibboleth headers; if the AuthUser *does* have a backing User, then update the
                // User from Shibboleth headers.
                final AuthUser u;
                if (authUser.getId() == null) {
                    LOG.debug("Creating new user");
                    u = createUser(authUser);
                } else {
                    LOG.debug("Updating user");
                    u = updateUser(authUser);
                }

                // If there is a user token, apply it to the submission.
                if (usertoken != null) {
                    applyUserToken(usertoken, u.getUser());
                }

                LOG.debug("Exiting critical section");
                return u;
            }, usertoken == null);
        } catch (final BadTokenException e) {
            try (Writer out = response.getWriter()) {
                LOG.warn("Sending 400 response due to token exception", e);
                response.setStatus(400);
                out.append(e.getMessage());
            }
            return;
        }

        // At this point, any eligible person will have an up to date User object in Fedora
        // if the person is not eligible, the shib user ID will be null

        if (shibUser.getId() == null) {
            LOG.info("{} not authorized", shibUser.getPrincipal());
            try (Writer out = response.getWriter()) {
                response.setStatus(401);
                out.append("Unauthorized");
            }
        } else {
            final User user = new User(shibUser.getUser());
            rewriteUri(user, request);

            LOG.debug("Successfully returning User data for {}", user.getId());
            try (OutputStream out = response.getOutputStream()) {
                out.write(json.toJson(user, true));
                response.setStatus(200);
            }
        }
    }

    private void applyUserToken(Token token, User user) {
        if (tokenService.enactUserToken(user, token)) {
            tokenService.addWritePermissions(user, token);
        }
    }

    private AuthUser createUser(AuthUser authUser) {
        final User user = new User();
        user.setUsername(authUser.getPrincipal());
        user.setLocatorIds(authUser.getLocatorIds());
        user.setDisplayName(authUser.getName());
        user.setEmail(authUser.getEmail());
        user.getRoles().add(User.Role.SUBMITTER);

        authUser.setUser(fedoraClient.createAndReadResource(user, User.class));
        authUser.setId(authUser.getUser().getId());

        LOG.info("Created new User resource <{}> for {})", authUser.getId(), user.getLocatorIds().get(0));
        return authUser;
    }

    private AuthUser updateUser(AuthUser shibUser) {
        User user = fedoraClient.readResource(shibUser.getId(), User.class);

        if (user == null) {
            throw new RuntimeException(String.format("Resource %s does not exist, this should never happen", shibUser
                    .getId()));
        }

        LOG.debug("Found existing user {}", shibUser.getId());

        boolean update = false;

        // each user provider will only adjust fields for which it is authoritative
        // shib is authoritative for these
        if (user.getUsername() == null || !user.getUsername().equals(shibUser.getPrincipal())) {
            user.setUsername(shibUser.getPrincipal());
            update = true;
        }
        if (user.getEmail() == null || !user.getEmail().equals(shibUser.getEmail())) {
            user.setEmail(shibUser.getEmail());
            update = true;
        }
        if (user.getDisplayName() == null || !user.getDisplayName().equals(shibUser.getName())) {
            user.setDisplayName(shibUser.getName());
            update = true;
        }

        //synchronize shared field
        if (user.getLocatorIds() == null || !user.getLocatorIds().containsAll(shibUser.getLocatorIds())) {
            user.getLocatorIds().addAll(shibUser.getLocatorIds());
            user.setLocatorIds(new ArrayList<>(new HashSet(user.getLocatorIds())));//remove duplicates
            update = true;
        }

        if (update) {
            LOG.info("User record for {} in repository is out of date, updating {} ", shibUser.getPrincipal(),
                    user.getId());
            user = fedoraClient.updateAndReadResource(user, User.class);
        } else {
            LOG.info("User record {} in repository is up to date, NOT updating", user.getId());
        }
        shibUser.setUser(user);
        shibUser.setId(user.getId());
        return shibUser;
    }

    private void rewriteUri(User user, HttpServletRequest request) {

        final Protocol proto = Protocol.of(request, user.getId());
        final Host host = Host.of(request, user.getId());

        final URI u = user.getId();

        try {
            user.setId(new URI(
                    proto.get(),
                    u.getUserInfo(),
                    host.getHost(),
                    host.getPort(),
                    u.getPath(),
                    u.getQuery(),
                    u.getFragment()));
        } catch (final URISyntaxException e) {
            throw new RuntimeException("Error rewriting URI " + user.getId());
        }

    }

    private static class Host {

        final String host;

        final int port;

        static Host of(HttpServletRequest request, URI defaults) {
            final String host = request.getHeader("host");
            if (host != null && host != "") {
                return new Host(host);
            } else {
                if (request.getRequestURL() != null) {
                    return new Host(URI.create(request.getRequestURL().toString()).getHost());
                } else {
                    return new Host(defaults.getHost(), defaults.getPort());
                }
            }
        }

        private Host(String host, int port) {
            this.host = host;
            this.port = port;
        }

        private Host(String hostname) {
            if (hostname.contains(":")) {
                final String[] parts = hostname.split(":");
                host = parts[0];
                port = Integer.valueOf(parts[1]);
            } else {
                host = hostname;
                port = -1;
            }
        }

        String getHost() {
            return host;
        }

        int getPort() {
            return port;
        }
    }

    private static class Protocol {

        final String proto;

        static Protocol of(HttpServletRequest request, URI defaults) {
            if (request.getHeader("X-Forwarded-Proto") != null) {
                return new Protocol(request.getHeader("X-Forwarded-Proto"));
            } else if (request.getRequestURL() != null) {
                return new Protocol(URI.create(request.getRequestURL().toString()).getScheme());
            } else {
                return new Protocol(defaults.getScheme());
            }
        }

        private Protocol(String proto) {
            this.proto = proto;
        }

        String get() {
            return proto;
        }
    }

}

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

package org.dataconservancy.pass.authz.roles;

import static java.util.Optional.ofNullable;
import static org.dataconservancy.pass.authz.ConfigUtil.getValue;
import static org.dataconservancy.pass.authz.roles.AuthRolesProvider.getRoles;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;
import org.dataconservancy.pass.authz.LogUtil;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class PassRolesFilter implements Filter {

    Logger LOG = LoggerFactory.getLogger(PassRolesFilter.class);

    public static final String DEFAULT_ROLE_HEADER = "pass-roles";

    public static final String PROP_ALLOW_EXTERNAL_ROLES = "authz.allow.external.roles";

    public static final String PROP_HEADER_NAME = "authz.header.name";

    public static final String PROP_HEADER_SEPARATOR = "authz.header.separator";

    public static final String PROP_USER_SERVICE_PATH = "authz.user.service.path";

    static final String USER_SERVICE_PATH = ofNullable(getValue(PROP_USER_SERVICE_PATH)).orElse("/pass-user-service");

    boolean allowExternalRoles;

    final String authzHeader = ofNullable(getValue(PROP_HEADER_NAME)).orElse(DEFAULT_ROLE_HEADER);

    final String authzRoleSeparator = ofNullable(getValue(PROP_HEADER_SEPARATOR)).orElse(",");

    Function<ServletContext, AuthUserProvider> authUserProviderFactory = (sc) -> {
        final ServletContext userServiceContext = sc.getContext(USER_SERVICE_PATH);

        if (userServiceContext == null) {
            throw new NullPointerException("Could not access the user service context");
        }

        final AuthUserProvider provider = (AuthUserProvider) userServiceContext.getAttribute("authUserProvider");

        if (provider == null) {
            throw new RuntimeException("Cannot get authUserProvider from /pass-user-service");
        }

        return provider;

    };

    final PassClient passClient;

    public PassRolesFilter() {
        LogUtil.adjustLogLevels();

        passClient = PassClientFactory.getPassClient();
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        LOG.info("Initializing filter");

        LOG.info("Using authz header {}", authzHeader);

        allowExternalRoles = new Boolean(ofNullable(getValue(PROP_ALLOW_EXTERNAL_ROLES)).orElse("false"));
        if (allowExternalRoles) {
            LOG.warn("Init: Allowing external values for authz header {}", authzHeader);
        }

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {

        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse resp = (HttpServletResponse) response;

        AuthzRequestWrapper rolesWrapper = null;
        try {
            if (!req.getRequestURI().startsWith(USER_SERVICE_PATH)) {
                LOG.debug("Preparing authorizations for {} {}", req.getMethod(), req.getRequestURL());
                rolesWrapper = new AuthzRequestWrapper(req);
            } else {
                // If the request is for the user service, just pass down the chain, don't apply the roles wrapper.
                chain.doFilter(request, response);
            }
        } catch (final Exception e) {
            LOG.warn("Could not apply roles filter", e);
            if (!resp.isCommitted()) {
                resp.sendError(500, "Error determining authorization roles.  This request has been logged.");
            }
        }

        if (rolesWrapper != null) {
            chain.doFilter(rolesWrapper, response);
        }

    }

    @Override
    public void destroy() {
        // nothing
    }

    class AuthzRequestWrapper extends HttpServletRequestWrapper {

        final String roles;

        public AuthzRequestWrapper(HttpServletRequest request) {
            super(request);

            final Set<String> rolesDiscovered = new HashSet<>();

            final String externalRoles = request.getHeader(authzHeader);

            if (allowExternalRoles && externalRoles != null) {
                LOG.warn("Accepting user-asserted roles '{}'", externalRoles);
                rolesDiscovered.addAll(Arrays.asList(externalRoles.split(authzRoleSeparator)));
            } else if (externalRoles != null) {
                LOG.warn("A request tried to assert roles '{}' in header '{}', but this is not allowed!  Discarding.",
                        externalRoles, authzHeader);
            }

            try {
                LOG.debug("Getting user info for roles");
                final AuthUser user = authUserProviderFactory.apply(request.getServletContext()).getUser(request,
                        a -> {
                            LOG.debug("Entering critical section");
                            if (a.getId() != null && a.getUser() == null) {
                                a.setUser(passClient.readResource(a.getId(), User.class));
                            }
                            LOG.debug("Exiting critical section");
                            return a;
                        }, true);

                rolesDiscovered.addAll(getRoles(user).stream()
                        .map(URI::toString)
                        .collect(Collectors.toList()));
            } catch (final Exception e) {
                throw new RuntimeException("Error looking up user or roles ", e);
            }

            roles = String.join(authzRoleSeparator, rolesDiscovered);

            LOG.debug("Using auth roles '{}'", roles);
        }

        @Override
        public String getHeader(String name) {
            if (authzHeader.equals(name)) {
                return roles;
            } else {
                return super.getHeader(name);
            }
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            final List<String> headers = Collections.list(super.getHeaderNames());
            if (!allowExternalRoles) {
                headers.add(authzHeader);
            } else if (!headers.contains(authzHeader)) {
                headers.add(authzHeader);
            }

            return Collections.enumeration(headers);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (authzHeader.equals(name)) {
                return Collections.enumeration(Arrays.asList(roles));
            } else {
                return super.getHeaders(name);
            }

        }
    }
}

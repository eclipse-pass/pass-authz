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

package org.dataconservancy.pass.authz.roles;

import static java.lang.String.format;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.client.fedora.FedoraConfig;
import org.dataconservancy.pass.model.User.Role;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides the authorization roles for a user
 * <p>
 * Returns their PASS User resource ID as their user role, and institution-scoped submitter/admin roles as defined in
 * their corresponding User object.
 * </p>
 * <p>
 * Uses an expiring LRU cache to cache the roles for a brief period of time.
 * </p>
 *
 * @author apb@jhu.edu
 */
public abstract class AuthRolesProvider {

    static final Logger LOG = LoggerFactory.getLogger(AuthRolesProvider.class);

    public static final String ROLE_BASE = "http://oapass.org/ns/roles/";

    public AuthRolesProvider() {
    }

    /**
     * Get all applicable authorization roles for a user.
     *
     * @param authUser The authenticated user.
     * @return All roles
     */
    public static Set<URI> getRoles(AuthUser authUser) {
        final Set<URI> roles = new HashSet<>();

        if (authUser == null) {
            LOG.warn("Authenticated user is null (this should never happen)");
            return roles;
        }

        if (authUser.getUser() == null) {
            if (authUser.getPrincipal() != null) {
                LOG.info("Authenticated user {} does not have a PASS User resource yet", authUser.getPrincipal());
            } else {
                LOG.debug("No principal provided, skipping lookup for roles");
            }
            return roles;
        }

        for (final String domain : authUser.getDomains()) {
            for (final Role role : authUser.getUser().getRoles()) {
                roles.add(getAuthRoleURI(domain, role));
            }
        }


        roles.addAll(addFedoraHack(authUser.getUser().getId()));

        LOG.debug("Found roles for {}: {}", authUser.getPrincipal(), roles);

        return roles;
    }

    public static URI getAuthRoleURI(String domain, Role role) {
        return URI.create(ROLE_BASE + format("%s#%s", domain, role));
    }

    // This is a hack for fcrepo4, whereby ACLs cannot use http fedora resource URIs.
    // For some unknown (and incorrect) reason, they need to begin with info:fedora.
    // Therefore, we just add the info:fedora variant.
    private static List<URI> addFedoraHack(URI resource) {

        final List<URI> roles = new ArrayList<>();
        roles.add(resource);
        if (resource.toString().startsWith(FedoraConfig.getBaseUrl())) {
            roles.add(URI.create(resource.toString().replace(FedoraConfig.getBaseUrl(), "info:fedora/")));
        }

        return roles;

    }
}

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

package org.dataconservancy.pass.authz.acl;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toSet;
import static org.dataconservancy.pass.client.fedora.RepositoryCrawler.Ignore.IGNORE_ROOT;
import static org.dataconservancy.pass.client.fedora.RepositoryCrawler.Skip.depth;
import static org.dataconservancy.pass.client.util.ConfigUtil.getSystemProperty;

import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

import org.dataconservancy.pass.client.fedora.FedoraConfig;
import org.dataconservancy.pass.client.fedora.RepositoryCrawler;
import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoClient.FcrepoClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates or deletes, or modifies ACLs to reflect desired permissions.
 *
 * @author apb@jhu.edu
 */
public class ACLManager {

    static final Logger LOG = LoggerFactory.getLogger(ACLManager.class);

    public static final String PROPERTY_ACL_BASE = "acl.base";

    public static final String URI_ACL_AGENT = "http://www.w3.org/ns/auth/acl#agent";

    public static final String URI_ACL_ACCESS_TO = "http://www.w3.org/ns/auth/acl#accessTo";

    public static final String URI_ACL_MODE = "http://www.w3.org/ns/auth/acl#mode";

    private static final String TEMPLATE_AUTHORIZATION =
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\n" +
                    "<> a acl:Authorization .\n" +
                    "<> acl:accessTo <%s> .\n";

    AclDriver driver;

    RepositoryCrawler crawler;

    public ACLManager() {
        driver = new AclDriver(getAclBase(), getFcrepoClient());
        this.crawler = new RepositoryCrawler();
    }

    public ACLManager(FcrepoClient client, RepositoryCrawler crawler) {
        driver = new AclDriver(getAclBase(), client);
        this.crawler = crawler;
    }

    public static URI getAclBase() {
        return URI.create(FedoraConfig.getBaseUrl() + getSystemProperty(PROPERTY_ACL_BASE, "acls"));
    }

    public Builder addPermissions(URI resource) {
        LOG.debug("Adding permissions to " + resource);
        return new Builder(resource, (builder, acl) -> {

            for (final Permission permission : builder.allPermissions()) {
                final URI authzResource = getAuthorizationResourceForPermission(acl, permission);

                final Set<URI> roles = builder.getRolesForPermission(permission);

                if (driver.exists(authzResource)) {
                    driver.patchAuthzBody(authzResource, patchInsert(resource, permission, roles));
                } else {
                    driver.putAuthzBody(authzResource, getAclBody(resource, permission, roles));
                }
            }
        });
    }

    public Builder setPermissions(URI resource) {
        LOG.debug("Setting permissions of " + resource);
        return new Builder(resource, (builder, acl) -> {

            for (final Permission permission : Permission.values()) {
                final URI authzResource = getAuthorizationResourceForPermission(acl, permission);

                final Set<URI> roles = builder.getRolesForPermission(permission);

                driver.putAuthzBody(authzResource, getAclBody(resource, permission, roles));
            }

            final Collection<URI> desiredAuthorizationResources = authzResourcesForAcl(acl);
            crawler.visit(acl, authz -> {
                if (!desiredAuthorizationResources.contains(authz)) {
                    driver.deleteCompletely(authz);
                }
            }, IGNORE_ROOT, depth(1));
        });
    }

    FcrepoClient getFcrepoClient() {
        return new FcrepoClientBuilder().credentials(FedoraConfig.getUserName(), FedoraConfig.getPassword()).build();
    }

    public URI getAuthorizationResource(URI resource, Permission permission) {
        try {
            return getAuthorizationResourceForPermission(driver.findOrCreateACL(resource).uri, permission);
        } catch (final Exception e) {
            throw new RuntimeException("Could not find ACL", e);
        }
    }

    public URI getAclResource(URI target) {
        try {
            return driver.findOrCreateACL(target).uri;
        } catch (final Exception e) {
            throw new RuntimeException("Could not find ACL", e);
        }
    }

    public class Builder {

        final URI resource;

        final Set<URI> read = new HashSet<>();

        final Set<URI> write = new HashSet<>();

        final BiConsumer<Builder, URI> action;

        Builder(URI resource, BiConsumer<Builder, URI> aclAction) {
            this.resource = resource;
            this.action = aclAction;
        }

        public Builder grantRead(Collection<URI> roles) {
            read.addAll(roles);
            return this;
        }

        public Builder grantWrite(Collection<URI> roles) {
            write.addAll(roles);
            read.addAll(roles);
            return this;
        }

        public Builder grantAppend(Collection<URI> roles) {
            write.addAll(roles);
            read.addAll(roles);
            return this;
        }

        public URI perform() {
            try {
                final Acl acl = driver.findOrCreateACL(resource);
                action.accept(this, acl.uri);
                if (acl.isNew) {
                    driver.linkAcl(acl.uri, resource);
                }
                return acl.uri;

            } catch (final Exception e) {
                throw new RuntimeException("Error communicating with repository", e);
            }
        }

        Set<URI> getRolesForPermission(Permission p) {
            switch (p) {
                case Read:
                    return read.stream().filter(not(write::contains)).collect(toSet());
                case Write:
                    return write;
                default:
                    return emptySet();
            }
        }

        Set<Permission> allPermissions() {
            final HashSet<Permission> permissions = new HashSet<>();
            if (!read.isEmpty()) {
                permissions.add(Permission.Read);
            }

            if (!write.isEmpty()) {
                permissions.add(Permission.Write);
            }

            return permissions;
        }
    }

    private static String getAclBody(URI resource, Permission permission, Collection<URI> roles) {
        final StringBuilder auth = new StringBuilder(format(TEMPLATE_AUTHORIZATION, resource));

        for (final URI role : roles) {
            auth.append(format("<> acl:agent <%s> .\n", role));
        }

        auth.append(permission.rdf);

        return auth.toString();
    }

    private static String patchInsert(URI protectedResource, Permission permission, Collection<URI> roles) {
        final StringBuilder patch = new StringBuilder(
                "PREFIX acl: <http://www.w3.org/ns/auth/acl#>\n\nINSERT {\n");

        patch.append(format("<> <%s> <%s> .\n", URI_ACL_ACCESS_TO, protectedResource));
        patch.append(permission.rdf);

        roles.forEach(role -> patch.append(format("<> <%s> <%s> .\n", URI_ACL_AGENT, role)));

        patch.append("} WHERE {}");

        return patch.toString();
    }

    private static URI getAuthorizationResourceForPermission(URI acl, Permission permission) {
        if (acl.toString().endsWith("/")) {
            return URI.create(acl.toString() + permission.toString());
        } else {
            return URI.create(acl.toString() + "/" + permission.toString());
        }
    }

    private static <T> Predicate<T> not(Predicate<T> predicate) {
        return t -> !predicate.test(t);
    }

    private static Collection<URI> authzResourcesForAcl(URI acl) {
        return asList(getAuthorizationResourceForPermission(acl, Permission.Read),
                getAuthorizationResourceForPermission(acl, Permission.Write));
    }
}

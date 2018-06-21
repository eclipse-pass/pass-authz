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

package org.dataconservancy.pass.authz.acl;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.apache.commons.io.IOUtils.toInputStream;
import static org.dataconservancy.pass.client.util.ConfigUtil.getSystemProperty;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoClient.FcrepoClientBuilder;
import org.fcrepo.client.FcrepoOperationFailedException;
import org.fcrepo.client.FcrepoResponse;

import org.dataconservancy.pass.client.fedora.FedoraConfig;

import org.apache.commons.io.IOUtils;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates or deletes, or modifies ACLs to reflect desired permissions.
 *
 * @author apb@jhu.edu
 */
public class ACLManager {

    static final Logger LOG = LoggerFactory.getLogger(ACLManager.class);

    URI PREFER_EMBED = URI.create("http://fedora.info/definitions/v4/repository#EmbedResources");

    URI PREFER_SERVER_MANAGED = URI.create("http://fedora.info/definitions/v4/repository#ServerManaged");

    URI PREFER_CONTAINMENT = URI.create("http://www.w3.org/ns/ldp#PreferContainment");

    URI PREDICATE_ACCESS_CONTROL = URI.create("http://www.w3.org/ns/auth/acl#accessControl");

    public final FcrepoClient repo;

    private final URI acls;

    static final String TEMPLATE_ADD_ACL_TRIPLE =
            "INSERT {<> <http://www.w3.org/ns/auth/acl#accessControl> <%s>} WHERE {}";

    static final String TEMPLATE_AUTHORIZATION =
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\n" +
                    "<> a acl:Authorization;\n" +
                    "acl:accessTo <%s>;\n" +
                    "acl:agent <%s> .\n";

    static final String READ_AUTH = "<> acl:mode acl:Read .\n";

    static final String WRITE_AUTH = "<> acl:mode acl:Write .\n";

    public ACLManager() {
        repo = getFcrepoClient();
        acls = getAclBase();
    }

    public ACLManager(FcrepoClient client) {
        repo = client;
        acls = getAclBase();
    }

    public static URI getAclBase() {
        return URI.create(FedoraConfig.getBaseUrl() + getSystemProperty("acl.base", "acls"));
    }

    public Builder addPermissions(URI resource) {
        return new Builder(resource, (builder, acl) -> {

            final AclAnalyzer analyzer = new AclAnalyzer(getFcrepoClient(), acl);

            for (final URI role : builder.allRoles()) {
                final URI authzResource = analyzer.getAuthorizationResourceForRole(role);

                if (authzResource == null) {
                    postAuthzBody(acl, builder.getAclBody(role));
                } else if (permissionsAreDifferent(role, builder, analyzer)) {
                    patchAuthzBody(authzResource, builder.patchInsert(role));
                } else {
                    LOG.debug("No ACL update necessary");
                }
            }
        });
    }

    public Builder setPermissions(URI resource) {
        return new Builder(resource, (builder, acl) -> {

            final AclAnalyzer analyzer = new AclAnalyzer(getFcrepoClient(), acl);

            final Set<URI> roles = new HashSet<>();

            roles.addAll(builder.allRoles());
            roles.addAll(analyzer.getAuthRoles());

            for (final URI role : roles) {

                final URI authzResource = analyzer.getAuthorizationResourceForRole(role);

                if (authzResource == null) {
                    postAuthzBody(acl, builder.getAclBody(role));
                } else if (permissionsAreDifferent(role, builder, analyzer)) {
                    putAuthzBody(authzResource, builder.getAclBody(role));
                } else {
                    LOG.debug("No ACL update necessary");
                }
            }
        });
    }

    public Builder setPermissionsForRoles(URI resource, Collection<URI> roles) {
        return new Builder(resource, (builder, acl) -> {
            final AclAnalyzer analyzer = new AclAnalyzer(getFcrepoClient(), acl);

            for (final URI role : roles) {

                final URI authzResource = analyzer.getAuthorizationResourceForRole(role);

                if (authzResource == null) {
                    postAuthzBody(acl, builder.getAclBody(role));
                } else if (permissionsAreDifferent(role, builder, analyzer)) {
                    putAuthzBody(authzResource, builder.getAclBody(role));
                } else {
                    LOG.debug("No ACL update necessary");
                }
            }
        });
    }

    FcrepoClient getFcrepoClient() {
        return new FcrepoClientBuilder().credentials(FedoraConfig.getUserName(), FedoraConfig.getPassword()).build();
    }

    private FcrepoClient repo() {
        return repo;
    }

    static boolean permissionsAreDifferent(URI role, Builder builder, AclAnalyzer acl) {
        final Set<Permission> permissions = acl.getPermissionsforRole(role);
        LOG.debug("read? (builder: {}, acl: {})", builder.read.contains(role), permissions.contains(Permission.Read));
        LOG.debug("write? (builder: {}, acl: {})", builder.write.contains(role), permissions.contains(
                Permission.Write));
        return builder.read.contains(role) != permissions.contains(Permission.Read) ||
                builder.write.contains(role) != permissions.contains(Permission.Write);

    }

    static void onErrorThrow(FcrepoResponse response, String message, Object... params) throws IOException {
        if (response.getStatusCode() > 299) {
            try (InputStream in = response.getBody()) {
                throw new RuntimeException(
                        format(message, params) + "; " +
                                response.getStatusCode() + ": " +
                                IOUtils.toString(in, UTF_8));
            }
        }

    }

    private void patchAuthzBody(URI authz, String body) {

        LOG.debug("PATCHing authz to <{}> with body\n{}", authz, body);
        try (FcrepoResponse response = repo().patch(authz)
                .body(IOUtils.toInputStream(body, UTF_8))
                .perform()) {
            onErrorThrow(response, "Error updating authorization at <%s>", authz);

        } catch (FcrepoOperationFailedException | IOException e) {
            throw new RuntimeException("Error conecting to the repository", e);
        }
    }

    private void putAuthzBody(URI authz, String body) {

        LOG.debug("PUTting authz to <{}> with body\n{}", authz, body);
        try (FcrepoResponse response = repo().put(authz)
                .body(IOUtils.toInputStream(body, UTF_8), "text/turtle")
                .preferLenient()
                .perform()) {
            onErrorThrow(response, "Error updating authorization at <%s>", authz);

        } catch (FcrepoOperationFailedException | IOException e) {
            throw new RuntimeException("Error conecting to the repository", e);
        }
    }

    private void postAuthzBody(URI acl, String body) {

        LOG.debug("POSTing authz to <{}> with body\n{}", acl, body);
        try (FcrepoResponse response = repo().post(acl)
                .body(IOUtils.toInputStream(body, UTF_8), "text/turtle")
                .perform()) {
            onErrorThrow(response, "Error adding authorization to acl <%s>", acl);

        } catch (FcrepoOperationFailedException | IOException e) {
            throw new RuntimeException("Error conecting to the repository", e);
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
            return this;
        }

        public Builder grantAppend(Collection<URI> roles) {
            write.addAll(roles);
            return this;
        }

        public URI perform() {
            try {
                final URI acl = findOrCreateACL();
                action.accept(this, acl);
                return acl;

            } catch (final Exception e) {
                throw new RuntimeException("Error communicating with repository", e);
            }
        }

        Set<URI> allRoles() {
            final HashSet<URI> all = new HashSet<>();
            all.addAll(read);
            all.addAll(write);
            return all;
        }

        URI findOrCreateACL() throws FcrepoOperationFailedException, IOException {

            LOG.debug("Finding ACL for <{}>", resource);
            try (FcrepoResponse response = repo.get(resource)
                    .accept("application/n-triples")
                    .preferRepresentation(emptyList(), asList(PREFER_CONTAINMENT, PREFER_SERVER_MANAGED)).perform()) {

                onErrorThrow(response, "Error looking for ACL");

                final List<URI> acls;
                final Model model = ModelFactory.createDefaultModel();
                try (InputStream body = response.getBody()) {
                    model.read(body, "", "NTriples");
                    acls = model.listStatements(null,
                            model.createProperty(PREDICATE_ACCESS_CONTROL.toString()),
                            (RDFNode) null)
                            .mapWith(s -> URI.create(s.getObject().asResource().toString()))
                            .toList();
                }

                if (acls.size() == 1) {
                    LOG.debug("Found existing ACL <{}>", acls.get(0));
                    return acls.get(0);
                } else if (acls.isEmpty()) {
                    LOG.debug("No ACL, on <{}> creating one", resource);

                    return createAcl(resource);
                } else {
                    throw new RuntimeException(format("More than one acl for resource <%s>: {%s}", resource,
                            String.join(",", acls.stream().map(URI::toString).collect(Collectors.toList()))));
                }
            }
        }

        String getAclBody(URI role) {
            final StringBuilder auth = new StringBuilder(format(TEMPLATE_AUTHORIZATION, resource, role));

            if (read.contains(role)) {
                auth.append(READ_AUTH);
            }

            if (write.contains(role)) {
                auth.append(WRITE_AUTH);
            }

            return auth.toString();
        }

        String patchInsert(URI role) {
            final StringBuilder patch = new StringBuilder(
                    "PREFIX acl: <http://www.w3.org/ns/auth/acl#>\n\nINSERT {\n");

            if (read.contains(role)) {
                patch.append(READ_AUTH);
            }

            if (write.contains(role)) {
                patch.append(WRITE_AUTH);
            }

            patch.append("} WHERE {}");

            return patch.toString();
        }

        private URI createAcl(URI resource) throws IOException, FcrepoOperationFailedException {
            final URI acl;
            try (FcrepoResponse response = repo.post(acls)
                    .body(this.getClass().getResourceAsStream("/acl.ttl"), "text/turtle")
                    .perform()) {
                onErrorThrow(response, "Error creating acl");
                acl = response.getLocation();
            }

            LOG.debug("Created ACL at <{}>", acl);

            LOG.debug("Linking ACL <{}> to <{}> via PATCH:\n{}", acl, resource, format(
                    TEMPLATE_ADD_ACL_TRIPLE, acl));

            try (FcrepoResponse response = repo.patch(resource)
                    .body(toInputStream(format(TEMPLATE_ADD_ACL_TRIPLE, acl), UTF_8)).perform()) {
                onErrorThrow(response, "Error linking to acl <%s> from <%s>", acl, resource);
                return acl;
            }
        }
    }
}

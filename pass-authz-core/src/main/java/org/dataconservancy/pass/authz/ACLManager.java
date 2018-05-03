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

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
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

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoClient.FcrepoClientBuilder;
import org.fcrepo.client.FcrepoOperationFailedException;
import org.fcrepo.client.FcrepoResponse;

import org.dataconservancy.pass.client.fedora.FedoraConfig;

import org.apache.commons.io.IOUtils;

/**
 * @author apb@jhu.edu
 */
public class ACLManager {

    private final FcrepoClient repo;

    private final URI acls;

    static final String TEMPLATE_ADD_ACL_TRIPLE =
            "INSERT {<> <http://www.w3.org/ns/auth/acl#accessControl> <%s>} WHERE {}";

    public ACLManager() {
        repo = getFcrepoClient();
        acls = getAclBase();
    }

    public ACLManager(FcrepoClient client) {
        repo = client;
        acls = getAclBase();
    }

    private static URI getAclBase() {
        return URI.create(FedoraConfig.getBaseUrl() + getSystemProperty("acl.base", "acls"));
    }

    public Builder addPermissions(URI resource) {
        return new Builder(resource, ADD_AUTHORIZATION);
    }

    FcrepoClient getFcrepoClient() {
        return new FcrepoClientBuilder().credentials(FedoraConfig.getUserName(), FedoraConfig.getPassword()).build();
    }

    private FcrepoClient repo() {
        return repo;
    }

    final BiConsumer<Builder, URI> ADD_AUTHORIZATION = (builder, acl) -> {

        // Get auth

        try (FcrepoResponse response = repo().post(acl)
                .body(IOUtils.toInputStream("", UTF_8), "text/turtle")
                .perform()) {
            onErrorThrow(response, "Error adding authorization to acl <%s> for <$s>", acl, builder.resource);

        } catch (FcrepoOperationFailedException | IOException e) {
            throw new RuntimeException("Error conecting to the repository", e);
        }
    };

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
            read.addAll(roles);
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

        private URI findOrCreateACL() throws FcrepoOperationFailedException, IOException {

            try (FcrepoResponse response = repo.head(resource).perform()) {
                final List<URI> acls = response.getLinkHeaders("acl");
                if (acls.size() == 1) {
                    return acls.get(0);
                } else {
                    return createAcl(resource);
                }
            }
        }

        private URI createAcl(URI resource) throws IOException, FcrepoOperationFailedException {
            final URI acl;
            try (FcrepoResponse response = repo.post(acls)
                    .body(this.getClass().getResourceAsStream("/acl.ttl"), "text/turtle")
                    .perform()) {
                onErrorThrow(response, "Error creating acl");
                acl = response.getLocation();
            }

            try (FcrepoResponse response = repo.patch(resource)
                    .body(toInputStream(format(TEMPLATE_ADD_ACL_TRIPLE, acl), UTF_8)).perform()) {
                onErrorThrow(response, "Error linking to acl <%s> from <%s>", acl, resource);
                return acl;
            }
        }
    }

    private static void onErrorThrow(FcrepoResponse response, String message, Object... params) throws IOException {
        if (response.getStatusCode() > 299) {
            try (InputStream in = response.getBody()) {
                throw new RuntimeException(format(message, params) + "; " + response.getStatusCode() +
                        ": " +
                        IOUtils.toString(in,
                                UTF_8));
            }
        }
    }
}

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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoClient.FcrepoClientBuilder;
import org.fcrepo.client.FcrepoOperationFailedException;
import org.fcrepo.client.FcrepoResponse;

import org.dataconservancy.pass.client.fedora.FedoraConfig;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class ACLManager {

    Logger LOG = LoggerFactory.getLogger(ACLManager.class);

    private final FcrepoClient repo;

    private final URI acls;

    static final Pattern aclPattern = Pattern.compile(
            ".+?\\s+<http://www.w3.org/ns/auth/acl#accessControl>\\s+<(.+?)>.+?");

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

        for (final URI role : builder.allRoles()) {
            final StringBuilder auth = aclAuth(builder.resource, role);

            if (builder.read.contains(role)) {
                auth.append(READ_AUTH);
            }

            if (builder.write.contains(role)) {
                auth.append(WRITE_AUTH);
            }

            postAuthzBody(acl, auth.toString());
        }
    };

    private static void onErrorThrow(FcrepoResponse response, String message, Object... params) throws IOException {
        if (response.getStatusCode() > 299) {
            try (InputStream in = response.getBody()) {
                throw new RuntimeException(
                        format(message, params) + "; " +
                                response.getStatusCode() + ": " +
                                IOUtils.toString(in, UTF_8));
            }
        }

    }

    private static StringBuilder aclAuth(URI toResource, URI role) {
        return new StringBuilder(format(TEMPLATE_AUTHORIZATION, toResource, role));
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
            try (FcrepoResponse response = repo.get(resource).accept("application/n-triples").perform()) {

                onErrorThrow(response, "Error looking for ACL");
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(response.getBody(), UTF_8))) {

                    final List<URI> acls = new ArrayList<>();

                    for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                        final Matcher aclFinder = aclPattern.matcher(line);
                        if (aclFinder.matches()) {
                            acls.add(URI.create(aclFinder.group(1)));
                        }
                    }

                    if (acls.size() == 1) {
                        LOG.debug("Found existing ACL <{}>", acls.get(0));
                        return acls.get(0);
                    } else {
                        LOG.debug("No ACL, on <{}> creating one", resource);

                        return createAcl(resource);
                    }
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

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
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.apache.commons.io.IOUtils.toInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoOperationFailedException;
import org.fcrepo.client.FcrepoResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class AclDriver {

    private static String TOMBSTONE = "fcr:tombstone";

    private static final Logger LOG = LoggerFactory.getLogger(AclDriver.class);

    URI PREFER_EMBED = URI.create("http://fedora.info/definitions/v4/repository#EmbedResources");

    URI PREFER_SERVER_MANAGED = URI.create("http://fedora.info/definitions/v4/repository#ServerManaged");

    URI PREFER_CONTAINMENT = URI.create("http://www.w3.org/ns/ldp#PreferContainment");

    URI PREDICATE_ACCESS_CONTROL = URI.create("http://www.w3.org/ns/auth/acl#accessControl");

    static final String TEMPLATE_ADD_ACL_TRIPLE =
            "INSERT {<> <http://www.w3.org/ns/auth/acl#accessControl> <%s>} WHERE {}";

    final FcrepoClient repo;

    final URI acls;

    AclDriver(final URI aclBase, final FcrepoClient repo) {
        this.repo = repo;
        this.acls = aclBase;
    }

    Acl findOrCreateACL(URI resource) throws FcrepoOperationFailedException, IOException {

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
                return new Acl(acls.get(0), false);
            } else if (acls.isEmpty()) {
                LOG.debug("No ACL, on <{}> creating one", resource);

                return createAcl(resource);
            } else {
                throw new RuntimeException(format("More than one acl for resource <%s>: {%s}", resource,
                        String.join(",", acls.stream().map(URI::toString).collect(Collectors.toList()))));
            }
        }
    }

    Acl createAcl(URI resource) throws IOException, FcrepoOperationFailedException {
        final URI acl;
        try (FcrepoResponse response = repo.post(acls)
                .body(this.getClass().getResourceAsStream("/acl.ttl"), "text/turtle")
                .perform()) {
            onErrorThrow(response, "Error creating acl by POSTing to " + acls);
            acl = response.getLocation();
        }

        LOG.debug("Created ACL at <{}>", acl);

        return new Acl(acl, true);
    }

    void linkAcl(URI acl, URI resource) throws IOException, FcrepoOperationFailedException {
        LOG.debug("Linking ACL <{}> to <{}> via PATCH:\n{}", acl, resource, format(
                TEMPLATE_ADD_ACL_TRIPLE, acl));

        try (FcrepoResponse response = repo.patch(resource)
                .body(toInputStream(format(TEMPLATE_ADD_ACL_TRIPLE, acl), UTF_8)).perform()) {
            onErrorThrow(response, "Error linking to acl <%s> from <%s>", acl, resource);
        }
    }

    void patchAuthzBody(URI authz, String body) {

        LOG.debug("PATCHing authz to <{}> with body\n{}", authz, body);
        try (FcrepoResponse response = repo.patch(authz)
                .body(IOUtils.toInputStream(body, UTF_8))
                .perform()) {
            onErrorThrow(response, "Error updating authorization at <%s>", authz);

        } catch (FcrepoOperationFailedException | IOException e) {
            throw new RuntimeException("Error conecting to the repository", e);
        }
    }

    void putAuthzBody(URI authz, String body) {

        LOG.debug("PUTting authz to <{}> with body\n{}", authz, body);
        try (FcrepoResponse response = repo.put(authz)
                .body(IOUtils.toInputStream(body, UTF_8), "text/turtle")
                .preferLenient()
                .perform()) {
            onErrorThrow(response, "Error updating authorization at <%s>", authz);

        } catch (FcrepoOperationFailedException | IOException e) {
            throw new RuntimeException("Error conecting to the repository", e);
        }
    }

    boolean exists(URI acl) {
        try (FcrepoResponse response = repo.head(acl)
                .perform()) {

            if (response.getStatusCode() == 404) {
                return false;
            }

            return true;

        } catch (FcrepoOperationFailedException | IOException e) {
            throw new RuntimeException("Error conecting to the repository", e);
        }
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

    void deleteCompletely(URI uri) {

        try (FcrepoResponse response = repo.delete(uri).perform()) {
            if (response.getStatusCode() == 404) {
                LOG.debug(uri + " already deleted");
            }

            onErrorThrow(response, "Could not delete resource %s", uri);

            consume(response);
            try (FcrepoResponse tombstoneRespinse = repo.delete(tombstoneFor(uri)).perform()) {
                onErrorThrow(response, "Could not delete tombstone %s", uri);
                consume(response);
            }
        } catch (final IOException | FcrepoOperationFailedException e) {
            throw new RuntimeException("Error conecting to the repository", e);
        }

    }

    static void consume(FcrepoResponse response) {
        try {
            if (response.getBody() != null) {
                IOUtils.toString(response.getBody(), UTF_8);
            }
        } catch (final Exception e) {
            LOG.info("Error consuming response", e);
        }
    }

    static URI tombstoneFor(URI uri) {
        if (uri.toString().endsWith("/")) {
            return URI.create(uri + TOMBSTONE);
        } else {
            return URI.create(uri + "/" + TOMBSTONE);
        }
    }
}
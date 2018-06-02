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
import static java.lang.String.join;
import static java.util.Arrays.asList;
import static org.dataconservancy.pass.authz.acl.ACLManager.onErrorThrow;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.util.HashSet;
import java.util.Set;

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoOperationFailedException;
import org.fcrepo.client.FcrepoResponse;

import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class AclAnalyzer {

    static final URI EMBED_RESOURCES = URI.create("http://fedora.info/definitions/v4/repository#EmbedResources");

    static final URI SERVER_MANAGED = URI.create("http://fedora.info/definitions/v4/repository#ServerManaged");

    static final Logger LOG = LoggerFactory.getLogger(AclAnalyzer.class);

    static final String FIND_PERMISSIONS =
            "PREFIX acl: <http://www.w3.org/ns/auth/acl#>\n" +
                    "SELECT ?mode \n" +
                    "WHERE {?auth acl:agent <%s> . \n" +
                    "?auth acl:mode ?mode }";

    Model model = ModelFactory.createDefaultModel();

    public AclAnalyzer() {

    }

    public AclAnalyzer(FcrepoClient client, URI acl) {
        try (FcrepoResponse response = client.get(acl)
                .accept("text/turtle")
                .preferRepresentation(asList(EMBED_RESOURCES), asList(SERVER_MANAGED)).perform()) {

            LOG.debug("Reading ACL {}", acl);
            model.read(response.getBody(), null, "TTL");

            if (LOG.isTraceEnabled()) {
                final StringWriter capture = new StringWriter();
                model.write(capture, "TTL");
                LOG.trace("Content of ACL {} is {}", acl, capture.toString());
            }

            onErrorThrow(response, "Could not read acl {}", acl);
        } catch (final IOException | FcrepoOperationFailedException e) {
            throw new RuntimeException("Could not connect to repository to analyze ACL ", e);
        }
    }

    public Set<Permission> getPermissionsforRole(URI role) {
        final Set<Permission> permissions = new HashSet<>();

        final String queryString = format(FIND_PERMISSIONS, role);
        LOG.trace("Getting permissions for role {} with query: \n {}", role, queryString);
        final Query query = QueryFactory.create(queryString);

        try (QueryExecution exec = QueryExecutionFactory.create(query, model)) {
            exec.execSelect().forEachRemaining(result -> permissions.add(
                    Permission.valueOf(result.getResource("mode").getLocalName())));
        }

        return permissions;
    }

    public URI getAuthorizationResourceForRole(URI role) {
        final Set<String> resources = model.listStatements(null, model.createProperty(
                "http://www.w3.org/ns/auth/acl#agent"),
                model.createResource(
                        role.toString())).mapWith(s -> s.getSubject().toString()).toSet();

        if (resources.size() > 1) {
            throw new RuntimeException("More than one authz resource for role " + role + ": " + join(", ",
                    resources));
        } else if (resources.isEmpty()) {
            LOG.debug("No authz resources for role {}", role);
            return null;
        }

        return URI.create(resources.iterator().next());
    }

    public Set<URI> getAuthRoles() {
        return model.listStatements(null, model.createProperty(
                "http://www.w3.org/ns/auth/acl#agent"), (RDFNode) null)
                .mapWith(s -> s.getObject())
                .filterKeep(o -> o.isResource())
                .mapWith(o -> URI.create(o.asResource().toString())).toSet();
    }
}

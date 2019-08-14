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

package org.dataconservancy.pass.authz.tools.main;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Optional.ofNullable;
import static org.dataconservancy.pass.authz.acl.ACLManager.getAclBase;
import static org.dataconservancy.pass.authz.tools.main.Const.ROLE_BASE_URI;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoClient.FcrepoClientBuilder;
import org.fcrepo.client.FcrepoResponse;

import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.client.fedora.FedoraConfig;

import org.apache.commons.io.IOUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * @author apb@jhu.edu
 */
public class ContainerPermissions {

    static URI containerBase;

    static URI roleBase;

    public static void main(String[] args) throws Exception {

        final ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

        final ObjectNode root = (ObjectNode) mapper.reader().readTree(ContainerPermissions.class.getResourceAsStream(
                "/containers.yml"));

        final ACLManager manager = new ACLManager();

        final FcrepoClient client = getFcrepoClient();

        containerBase = URI.create(ofNullable(FedoraConfig.getBaseUrl()).orElse(root.get("container-base").asText()));
        roleBase = ROLE_BASE_URI.orElse(URI.create(root.get("role-base").asText()));

        try (FcrepoResponse response = client.head(getAclBase()).perform()) {
            if (response.getStatusCode() == 404) {
                try (FcrepoResponse createResp = client.put(getAclBase()).perform()) {
                    System.err.println(createResp.getStatusCode());
                }
            }
        }

        for (final JsonNode node : (Iterable<JsonNode>) () -> root.get("containers").elements()) {
            final Map.Entry<String, JsonNode> entry = node.fields().next();

            final URI container = toUri(containerBase, entry.getKey());
            final ObjectNode permissions = (ObjectNode) entry.getValue();

            final Set<URI> readers = new HashSet<>();
            readers.addAll(getRoles(permissions.get("read")));
            readers.addAll(getRoles(permissions.get("write")));
            readers.addAll(getRoles(permissions.get("append")));

            System.out.println("Setting permissions of " + container);
            System.out.println("      read:  " + readers);
            System.out.println("    append:  " + getRoles(permissions.get("append")));
            System.out.println("     write:  " + getRoles(permissions.get("write")));

            // Create container if not present.
            try (FcrepoResponse response = client.head(container).perform()) {
                if (response.getStatusCode() == 404) {
                    try (FcrepoResponse putResponse = client.put(container).perform()) {
                        if (!(putResponse.getStatusCode() < 299)) {
                            System.out.println(IOUtils.toString(putResponse.getBody(), UTF_8));
                        } else {
                            System.out.println("Created new resource " + IOUtils.toString(putResponse.getBody(),
                                    UTF_8));
                        }
                    }
                }
            }

            manager.setPermissions(container)
                    .grantRead(new ArrayList<>(readers))
                    .grantWrite(getRoles(permissions.get("write")))
                    .grantAppend(getRoles(permissions.get("append"))).perform();

        }

    }

    static List<URI> getRoles(JsonNode node) {
        final List<URI> roles = new ArrayList<>();
        if (node != null && node.isArray()) {
            ((ArrayNode) node).forEach(e -> {
                roles.add(toUri(roleBase, e.asText()));
            });
        }
        return roles;
    }

    static URI toUri(URI base, String path) {
        if (base != null) {
            if (path.startsWith("http://") || path.startsWith("https://")) {
                return URI.create(path);
            } else {
                String b = base.toString();
                if (!b.endsWith("/") && !b.endsWith("#")) {
                    b += "/";
                }

                if (path.startsWith("/")) {
                    return URI.create(b + path.substring(1));
                } else {
                    return URI.create(b + path);
                }
            }
        } else {
            return URI.create(path);
        }
    }

    private static FcrepoClient getFcrepoClient() {
        return new FcrepoClientBuilder().credentials(FedoraConfig.getUserName(), FedoraConfig.getPassword()).build();
    }

}

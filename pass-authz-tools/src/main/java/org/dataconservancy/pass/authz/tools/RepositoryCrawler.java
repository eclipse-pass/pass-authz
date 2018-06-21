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

package org.dataconservancy.pass.authz.tools;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoClient.FcrepoClientBuilder;
import org.fcrepo.client.FcrepoResponse;

import org.dataconservancy.pass.client.fedora.FedoraConfig;

/**
 * @author apb@jhu.edu
 */
public class RepositoryCrawler {

    FcrepoClient client = new FcrepoClientBuilder().credentials(FedoraConfig.getUserName(), FedoraConfig
            .getPassword()).build();

    static final URI PREFER_CONTAINMENT = URI.create("http://www.w3.org/ns/ldp#PreferContainment");

    static final Pattern childPattern = Pattern.compile(
            ".+?\\s+<http://www.w3.org/ns/ldp#contains>\\s+<(.+?)>.+?");

    public int visit(URI resource, Consumer<URI> consumer) {

        int count = 1;

        consumer.accept(resource);

        final List<URI> children;
        if (resource.toString().matches(".+?fcrepo/rest/{0,1}[^/]{0,}/{0,1}$")) {
            System.out.println("Finding children of " + resource);
            children = getChildren(resource);
        } else {
            children = emptyList();
        }

        for (final URI child : children) {
            count += visit(child, consumer);
        }

        return count;
    }

    List<URI> getChildren(URI resource) {
        try (final FcrepoResponse response = client.get(resource)
                .accept("application/n-triples")
                .preferRepresentation(asList(PREFER_CONTAINMENT),
                        emptyList()).perform()) {

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(response.getBody(), UTF_8))) {

                final List<URI> children = new ArrayList<>();

                for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                    final Matcher aclFinder = childPattern.matcher(line);
                    if (aclFinder.matches()) {
                        children.add(URI.create(aclFinder.group(1)));
                    }
                }

                return children;
            }

        } catch (final Exception e) {
            throw new RuntimeException("Error getting children of " + resource, e);
        }
    }
}

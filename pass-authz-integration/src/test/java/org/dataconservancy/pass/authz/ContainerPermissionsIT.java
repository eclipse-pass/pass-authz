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

import static org.dataconservancy.pass.authz.JarRunner.jar;
import static org.dataconservancy.pass.client.fedora.RepositoryCrawler.Ignore.IGNORE_ROOT;
import static org.dataconservancy.pass.client.fedora.RepositoryCrawler.Skip.SKIP_NONE;
import static org.dataconservancy.pass.client.fedora.RepositoryCrawler.Skip.depth;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URI;

import org.dataconservancy.pass.client.fedora.FedoraConfig;
import org.dataconservancy.pass.client.fedora.RepositoryCrawler;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.junit.Test;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class ContainerPermissionsIT extends FcrepoIT {

    static CloseableHttpClient client = getHttpClient();

    @Test
    public void createResourcesIT() throws Exception {
        final RepositoryCrawler crawler = new RepositoryCrawler();

        // Delete everything!!

        final int numContainers = crawler.visit(URI.create(FedoraConfig.getBaseUrl()), ContainerPermissionsIT::delete,
                IGNORE_ROOT, SKIP_NONE.or(depth(1)));
        assertTrue(numContainers > 0);

        // Make sure we deleted
        assertEquals(0, crawler.visit(URI.create(FedoraConfig.getBaseUrl()), (uri) -> {
        }, IGNORE_ROOT, SKIP_NONE));

        // Now run the jar
        final Process runner = jar(new File(System.getProperty("authz.containerPermissions.jar").toString()))
                .logOutput(LoggerFactory.getLogger("container_permissions"))
                .withEnv("PASS_FEDORA_BASEURL", System.getProperty("pass.fedora.baseurl"))
                .withEnv("PASS_FEDORA_USER", System.getProperty("pass.fedora.user"))
                .withEnv("LOG.org.dataconservancy.pass.authz", "DEBUG").start();

        attempt(30, () -> {
            if (!runner.isAlive()) {
                return;
            }
            throw new RuntimeException("Still running");
        });

        assertTrue(crawler.visit(URI.create(FedoraConfig.getBaseUrl()), (uri) -> {
        }, IGNORE_ROOT, SKIP_NONE) >= numContainers);

    }

    static void delete(URI resource) {
        try (CloseableHttpResponse resp = client.execute(new HttpDelete(resource))) {
            if (resp.getStatusLine().getStatusCode() > 299) {
                throw new RuntimeException("Could not delete resource: " + resource + "; \n" + EntityUtils.toString(
                        resp.getEntity()));
            } else {
                EntityUtils.consume(resp.getEntity());

                final HttpDelete deleteTombstone = new HttpDelete(resource.toString() +
                        "/fcr:tombstone");
                try (CloseableHttpResponse tomb = client.execute(deleteTombstone)) {
                    if (tomb.getStatusLine().getStatusCode() > 299) {
                        throw new RuntimeException("Could not delete tombstone: " + deleteTombstone.getURI() +
                                " ;\n" + EntityUtils.toString(resp
                                        .getEntity()));
                    } else {
                        EntityUtils.consume(tomb.getEntity());
                    }
                }
            }
        } catch (final IOException e) {
            throw new RuntimeException("Could not delete resource", e);
        }
    }

}

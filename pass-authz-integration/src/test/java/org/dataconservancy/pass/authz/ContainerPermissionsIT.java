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
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URI;

import org.apache.http.impl.client.CloseableHttpClient;
import org.dataconservancy.pass.client.fedora.FedoraConfig;
import org.dataconservancy.pass.client.fedora.RepositoryCrawler;
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

        // Delete everything, except ACLS on the root (but DO delete the acls container)
        final int numDeleted = crawler.visit(URI.create(FedoraConfig.getBaseUrl()), FcrepoIT::deleteCompletely,
                IGNORE_ROOT.or(s -> s.id.toString().contains("acl")), SKIP_NONE.or(depth(1)));
        assertTrue(numDeleted > 0);

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
        }, IGNORE_ROOT, SKIP_NONE) >= numDeleted);

    }
}

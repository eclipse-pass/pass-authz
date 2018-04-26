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

import java.net.URI;
import java.util.concurrent.Callable;

import org.dataconservancy.pass.client.fedora.FedoraConfig;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

/**
 * @author apb@jhu.edu
 */
public abstract class FcrepoIT {

    static final String FCREPO_BASE_URI = String.format("http://localhost:%s/%s/rest/", System.getProperty(
            "FCREPO_PORT", "8080"), System.getProperty("fcrepo.cxtPath", "fcrepo"));

    static final URI USER_SERVICE_URI = URI.create(String.format("http://localhost:%s/pass-user-service/whoami",
            System.getProperty("FCREPO_PORT", "8080")));

    static {
        if (System.getProperty("pass.fedora.baseurl") == null) {
            System.setProperty("pass.fedora.baseurl", "http://localhost:8080/fcrepo/rest/");
        }
    }

    CloseableHttpClient getHttpClient() {
        final CredentialsProvider provider = new BasicCredentialsProvider();
        final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(FedoraConfig.getUserName(),
                FedoraConfig.getPassword());
        provider.setCredentials(AuthScope.ANY, credentials);

        return HttpClientBuilder.create()
                .setDefaultCredentialsProvider(provider)
                .build();

    }

    <T> T attempt(final int times, final Callable<T> it) {

        Throwable caught = null;

        for (int tries = 0; tries < times; tries++) {
            try {
                return it.call();
            } catch (final Throwable e) {
                caught = e;
                try {
                    Thread.sleep(1000);
                    System.out.println(".");
                } catch (final InterruptedException i) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        throw new RuntimeException("Failed executing task", caught);
    }
}

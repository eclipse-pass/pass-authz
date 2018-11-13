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

import static org.dataconservancy.pass.client.fedora.RepositoryCrawler.Ignore.IGNORE_NONE;
import static org.dataconservancy.pass.client.fedora.RepositoryCrawler.Skip.SKIP_NONE;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.Callable;

import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.authz.acl.Permission;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.client.fedora.FedoraConfig;
import org.dataconservancy.pass.client.fedora.RepositoryCrawler;

import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * @author apb@jhu.edu
 */
public abstract class FcrepoIT {

    static final String FCREPO_BASE_URI = String.format("http://%s:%s/%s/rest/",
            System.getProperty("FCREPO_HOST", "localhost"),
            System.getProperty("FCREPO_PORT", "8080"),
            System.getProperty("fcrepo.cxtPath", "fcrepo"));

    static final URI USER_SERVICE_URI = URI.create(String.format("http://%s:%s/pass-user-service/whoami",
            System.getProperty("FCREPO_HOST", "localhost"),
            System.getProperty("FCREPO_PORT", "8080")));

    static final String AUTH_ROLE_HEADER = "some-header";

    static final CloseableHttpClient client = getAuthClient(FedoraConfig.getUserName(), FedoraConfig.getPassword());

    static {
        if (System.getProperty("pass.fedora.user") == null) {
            System.setProperty("pass.fedora.user", "fedoraAdmin");
        }

        if (System.getProperty("pass.fedora.baseurl") == null) {
            System.setProperty("pass.fedora.baseurl", "http://localhost:8080/fcrepo/rest/");
        }

        if (System.getProperty("pass.elasticsearch.url") == null) {
            System.setProperty("pass.elasticsearch.url", "http://localhost:9200/pass/");
        }
    }

    @BeforeClass
    public static void addAclContainer() throws Exception {
        final HttpPut put = new HttpPut(FCREPO_BASE_URI + System.getProperty("acl.base", "acls"));
        final HttpHead head = new HttpHead(put.getURI());

        final int code = client.execute(head, r -> {
            return r.getStatusLine().getStatusCode();
        });

        if (code == 404) {
            client.execute(put, r -> {
                assertSuccess(put.getURI(), r);
                return URI.create(r.getFirstHeader("Location").getValue());
            });
        }
    }

    @AfterClass
    public static void cleanUp() {
        PassClientFactory.getPassClient().processAllEntities(FcrepoIT::deleteCompletely);
    }

    static void deleteCompletely(URI resource) {
        System.out.println("Deleting completely " + resource);
        try (CloseableHttpResponse resp = client.execute(new HttpDelete(resource))) {
            if (resp.getStatusLine().getStatusCode() == 404) {
                System.out.println("Resource already deleted:" + resource);
                EntityUtils.consume(resp.getEntity());
            } else if (resp.getStatusLine().getStatusCode() > 299) {
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

    /* Get a client with default/system username and password (fedoraAdmin) */
    static CloseableHttpClient getHttpClient() {
        return client;
    }

    /* Get a client with specific username and password */
    static CloseableHttpClient getAuthClient(String user, String password) {
        final CredentialsProvider provider = new BasicCredentialsProvider();
        final UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(user,
                password);
        provider.setCredentials(AuthScope.ANY, credentials);

        return HttpClientBuilder.create()
                .setDefaultCredentialsProvider(provider)
                .build();
    }

    static void assertSuccess(URI resource, HttpResponse response, String... messages) {
        if (response.getStatusLine().getStatusCode() > 299) {
            try {
                final StringBuilder message = new StringBuilder(String.join("\n", messages));
                if (response.getStatusLine().getStatusCode() == 403) {
                    final ACLManager mgr = new ACLManager();

                    message.append("\nRead authz: " + responseBody(mgr.getAuthorizationResource(resource,
                            Permission.Read)));
                    message.append("\nWrite authz: " + responseBody(mgr.getAuthorizationResource(resource,
                            Permission.Write)));

                    new RepositoryCrawler().visit(mgr.getAclResource(URI.create(FCREPO_BASE_URI)), uri -> {
                        message.append("\nRoot acl resource" + uri + ":\n" + responseBody(uri));
                    }, IGNORE_NONE, SKIP_NONE);

                    message.append("\n\n " + EntityUtils.toString(response.getEntity()));
                }
                fail("Http request failed: " + response.getStatusLine() + "; " + message.toString());
            } catch (final Exception e) {
                fail("Http request failed: " + response.getStatusLine());
            }
        }
    }

    static String responseBody(URI uri) {
        try (CloseableHttpResponse response = client.execute(new HttpGet(uri))) {
            if (response.getStatusLine().getStatusCode() == 200) {
                return EntityUtils.toString(response.getEntity());
            } else {
                return Integer.toString(response.getStatusLine().getStatusCode());
            }
        } catch (final Exception e) {
            return "XXX";
        }
    }

    static void attempt(final int times, final Runnable it) {
        attempt(times, () -> {
            it.run();
            return null;
        });
    }

    static <T> T attempt(final int times, final Callable<T> it) {

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

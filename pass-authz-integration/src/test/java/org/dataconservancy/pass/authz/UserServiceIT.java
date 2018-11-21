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

package org.dataconservancy.pass.authz;

import static java.util.Arrays.asList;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.DISPLAY_NAME_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMAIL_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EPPN_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.HOPKINS_ID_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.HOPKINS_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.JHED_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.SCOPED_AFFILIATION_HEADER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.authz.usertoken.Key;
import org.dataconservancy.pass.authz.usertoken.Token;
import org.dataconservancy.pass.authz.usertoken.TokenFactory;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.client.PassJsonAdapter;
import org.dataconservancy.pass.client.adapter.PassJsonAdapterBasic;
import org.dataconservancy.pass.client.util.ConfigUtil;
import org.dataconservancy.pass.model.Submission;
import org.dataconservancy.pass.model.User;
import org.dataconservancy.pass.model.support.Identifier;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.fusesource.hawtbuf.ByteArrayInputStream;
import org.junit.Assert;
import org.junit.Test;

import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * @author apb@jhu.edu
 */
public class UserServiceIT extends FcrepoIT {

    PassJsonAdapter json = new PassJsonAdapterBasic();

    final PassClient passClient = PassClientFactory.getPassClient();

    OkHttpClient httpClient = new OkHttpClient.Builder()
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build();

    String domain = "johnshopkins.edu";

    @Test
    public void testGivenUserDoesExistReturns200() throws Exception {

        final User newUser = new User();
        newUser.setFirstName("Bugs");
        newUser.setLastName("Bunny");
        final String eeId = new Identifier(domain, EMPLOYEE_ID_TYPE, "10933511").serialize();
        newUser.getLocatorIds().add(eeId);
        final String hkId = new Identifier(domain, HOPKINS_ID_TYPE, "LSDFER").serialize();
        newUser.getLocatorIds().add(hkId);
        newUser.getLocatorIds().add(new Identifier(domain, JHED_ID_TYPE, "bbunny1").serialize());
        newUser.getRoles().add(User.Role.SUBMITTER);

        final PassClient passClient = PassClientFactory.getPassClient();
        final URI id = passClient.createResource(newUser);

        attempt(60, () -> Assert.assertNotNull(passClient.findByAttribute(User.class, "locatorIds", hkId)));

        final Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(DISPLAY_NAME_HEADER, "Bugs Bunny");
        shibHeaders.put(EMAIL_HEADER, "bugs@jhu.edu");
        shibHeaders.put(EPPN_HEADER, "bbunny1@johnshopkins.edu");
        shibHeaders.put(SCOPED_AFFILIATION_HEADER, "SOCIOPATH@jhu.edu;FACULTY@jhu.edu");
        shibHeaders.put(EMPLOYEE_ID_HEADER, "10933511");
        shibHeaders.put(HOPKINS_ID_HEADER, "LSDFER@johnshopkins.edu");

        final String jhedId = new Identifier(domain, JHED_ID_TYPE, "bbunny1").serialize();

        final Request get = buildShibRequest(shibHeaders);
        final User fromResponse;
        try (Response response = httpClient.newCall(get).execute()) {
            final byte[] body = response.body().bytes();
            fromResponse = json.toModel(body, User.class);
            Assert.assertEquals(200, response.code());
            assertIsjsonld(body);
        }

        final User passUser = passClient.readResource(id, User.class);

        // these fields should be updated on this user
        assertTrue(passUser.getLocatorIds().contains(eeId));
        assertTrue(passUser.getLocatorIds().contains(jhedId));
        assertEquals(passUser.getLocatorIds().size(), fromResponse.getLocatorIds().size());
        assertEquals("Bugs Bunny", passUser.getDisplayName());
        assertEquals("bugs@jhu.edu", passUser.getEmail());
        assertEquals(passUser.getId(), fromResponse.getId());

    }

    @Test
    public void tokenAfterLoginTest() throws Exception {

        // This will first visit the user service without a token (to create a User), then later on invoke the user
        // service with a token.
        doTokenTest(true);
    }

    @Test
    public void tokenTest() throws Exception {

        // Simply invoke the user service with a token from the start.
        doTokenTest(false);
    }

    private void doTokenTest(boolean loginFirst) throws Exception {
        final Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(DISPLAY_NAME_HEADER, "Daffy Duck");
        shibHeaders.put(EMAIL_HEADER, "daffy@jhu.edu");
        shibHeaders.put(EPPN_HEADER, "dduck1@johnshopkins.edu");
        shibHeaders.put(HOPKINS_ID_HEADER, "DDDDDD@johnshopkins.edu");
        shibHeaders.put(SCOPED_AFFILIATION_HEADER, "TARGET@jhu.edu;STAFF@jhmi.edu");
        final String number = Integer.toString(ThreadLocalRandom.current().nextInt(1000,
                99999));
        shibHeaders.put(EMPLOYEE_ID_HEADER, number);

        final String eeId = new Identifier(domain, EMPLOYEE_ID_TYPE, number).serialize();

        assertNull(passClient.findByAttribute(User.class, "locatorIds", eeId));

        final URI MAILTO_PLACEHOLDER = URI.create("mailto:Daffy%20Duck%20%3Cdduck%40gmail.com%3E");

        // First, add a new submission, and make it writable by someone else;
        final Submission submission = new Submission();
        submission.setSubmitterName("My name");
        submission.setSubmitterEmail(MAILTO_PLACEHOLDER);
        final URI SUBMISSION_URI = passClient.createResource(submission);
        new ACLManager().setPermissions(SUBMISSION_URI).grantWrite(asList(URI.create(
                "http://example.org/nobody"))).perform();

        // Next, if desired try to log in to the user service first, without a token. This will create a User.
        if (loginFirst) {
            try (Response response = httpClient.newCall(buildShibRequest(shibHeaders)).execute()) {
                final byte[] body = response.body().bytes();
                json.toModel(body, User.class);
                Assert.assertEquals(200, response.code());
                assertIsjsonld(body);
            }
        }

        // We're going to use this request (an empty POST) to test whether we can write to a submission or not.
        final Request tryWrite = buildShibRequest(new Request.Builder()
                .post(RequestBody.create(null, "")),
                shibHeaders, SUBMISSION_URI, null);

        // Then, verify that a user the user can't write
        try (Response response = httpClient.newCall(tryWrite).execute()) {
            assertEquals(403, response.code());
            response.body().bytes();
        }

        // Next, give the user service a token.
        final Token token = new TokenFactory(ConfigUtil.getSystemProperty(Key.USER_TOKEN_KEY_PROPERTY,
                "BETKPFHWGGDIEWIIYKYQ33LUS4"))
                        .forPassResource(SUBMISSION_URI).withReference(MAILTO_PLACEHOLDER);

        final Request userServiceWithToken = buildShibRequest(shibHeaders, token);
        try (Response response = httpClient.newCall(userServiceWithToken).execute()) {
            final byte[] body = response.body().bytes();
            Assert.assertEquals(new String(body), 200, response.code());
            json.toModel(body, User.class);
            assertIsjsonld(body);
        }

        // Lastly, verify that a user the user can now write
        try (Response response = httpClient.newCall(tryWrite).execute()) {
            assertEquals("Failed writing to " + SUBMISSION_URI, 201, response.code());
            response.body().bytes();
        }
    }

    /* Makes sure that only one new user is created in the face of multiple concurrent requests */
    @Test
    public void testConcurrentNewUser() throws Exception {
        final ExecutorService exe = Executors.newFixedThreadPool(8);

        final Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(DISPLAY_NAME_HEADER, "Wot Gorilla");
        shibHeaders.put(EMAIL_HEADER, "gorilla@jhu.edu");
        shibHeaders.put(EPPN_HEADER, "wotg1@johnshopkins.edu");
        shibHeaders.put(SCOPED_AFFILIATION_HEADER, "TARGET@jhu.edu;FACULTY@jhmi.edu");
        shibHeaders.put(EMPLOYEE_ID_HEADER, "89248104");
        shibHeaders.put(HOPKINS_ID_HEADER, "WGWGWG@" + domain);

        final List<Future<User>> results = new ArrayList<>();

        final Request get = buildShibRequest(shibHeaders);
        try (Response response = httpClient.newCall(get).execute()) {
            Assert.assertEquals(200, response.code());
        }
        for (int i = 0; i < 8; i++) {
            results.add(exe.submit(() -> {
                try (Response response = httpClient.newCall(get).execute()) {
                    Assert.assertEquals(200, response.code());
                    return json.toModel(response.body().bytes(), User.class);
                }
            }));
        }

        final Set<URI> created = results.stream()
                .map(f -> {
                    try {
                        return f.get();
                    } catch (final Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .map(User::getId)
                .collect(Collectors.toSet());

        Assert.assertEquals(1, created.size());
        final String eeId = new Identifier(domain, EMPLOYEE_ID_TYPE, "89248104").serialize();
        attempt(60, () -> {
            Assert.assertNotNull(passClient.findByAttribute(User.class, "locatorIds", eeId));
        });

        exe.shutdown();
    }

    /* Makes sure that only one new user is created in the face of multiple concurrent requests */
    @Test
    public void testConcurrentNewUserWithToken() throws Exception {
        final ExecutorService exe = Executors.newFixedThreadPool(8);

        final URI MAILTO_PLACEHOLDER = URI.create("mailto:Daffy%20Duck%20%3Cdduck%40gmail.com%3E");
        final String EMPLOYEE_ID = Integer.toString(ThreadLocalRandom.current().nextInt(1000,
                99999));

        // First, add a new submission, and make it writable by someone else;
        final Submission submission = new Submission();
        submission.setSubmitterName("My name");
        submission.setSubmitterEmail(MAILTO_PLACEHOLDER);
        final URI SUBMISSION_URI = passClient.createResource(submission);
        new ACLManager().setPermissions(SUBMISSION_URI).grantWrite(asList(URI.create(
                "http://example.org/nobody"))).perform();

        final Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(DISPLAY_NAME_HEADER, "Wot Gorilla");
        shibHeaders.put(EMAIL_HEADER, "gorilla@jhu.edu");
        shibHeaders.put(EPPN_HEADER, "testConcurrentNewUserWithToken@johnshopkins.edu");
        shibHeaders.put(SCOPED_AFFILIATION_HEADER, "TARGET@jhu.edu;FACULTY@jhmi.edu");
        shibHeaders.put(EMPLOYEE_ID_HEADER, EMPLOYEE_ID);
        shibHeaders.put(HOPKINS_ID_HEADER, "testConcurrentNewUserWithToken@" + domain);

        // Next, build a token to give to the user service
        final Token token = new TokenFactory(ConfigUtil.getSystemProperty(Key.USER_TOKEN_KEY_PROPERTY,
                "BETKPFHWGGDIEWIIYKYQ33LUS4"))
                        .forPassResource(SUBMISSION_URI).withReference(MAILTO_PLACEHOLDER);

        // Build user service requests with and without tokens
        final Request userServiceWithoutToken = buildShibRequest(shibHeaders);
        final Request userServiceWithToken = buildShibRequest(shibHeaders, token);

        // We'll concurrently interleave requests that have user tokens vs not
        final List<Future<User>> results = new ArrayList<>();
        for (int i = 0; i < 8; i++) {

            if ((i & 1) == 0) {
                results.add(exe.submit(() -> {
                    try (Response response = httpClient.newCall(userServiceWithToken).execute()) {
                        Assert.assertEquals(200, response.code());
                        return json.toModel(response.body().bytes(), User.class);
                    }
                }));
            } else {
                results.add(exe.submit(() -> {
                    try (Response response = httpClient.newCall(userServiceWithoutToken).execute()) {
                        Assert.assertEquals(200, response.code());
                        return json.toModel(response.body().bytes(), User.class);
                    }
                }));
            }
        }

        final Set<URI> created = results.stream()
                .map(f -> {
                    try {
                        return f.get();
                    } catch (final Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .map(User::getId)
                .collect(Collectors.toSet());

        // Make sure only one User resource was created.
        Assert.assertEquals(1, created.size());

        // Make sure we can find the user
        final String eeId = new Identifier(domain, EMPLOYEE_ID_TYPE, EMPLOYEE_ID).serialize();
        attempt(60, () -> {
            Assert.assertNotNull(passClient.findByAttribute(User.class, "locatorIds", eeId));
        });

        // Make sure the submission has the new user as the submitter
        final Submission finalSubmissionState = passClient.readResource(SUBMISSION_URI, Submission.class);
        assertEquals(finalSubmissionState.getSubmitter(), created.iterator().next());

        exe.shutdown();
    }

    private Request buildShibRequest(Request.Builder builder, Map<String, String> headers, URI uri, Token token)
            throws MalformedURLException {

        final URI requestUri;

        if (token != null) {
            requestUri = token.addTo(uri);
        } else {
            requestUri = uri;
        }

        // Add the shib headers, and use a non-privileged Tomcat account to bypass Tomcat auth, yet be subject to the
        // roles filter and fcrepo auth.
        return builder.url(requestUri.toURL())
                .header("Authorization", Credentials.basic("user", "moo"))
                .header(DISPLAY_NAME_HEADER, headers.get(DISPLAY_NAME_HEADER))
                .header(EMAIL_HEADER, headers.get(EMAIL_HEADER))
                .header(EPPN_HEADER, headers.get(EPPN_HEADER))
                .header(SCOPED_AFFILIATION_HEADER, headers.get(SCOPED_AFFILIATION_HEADER))
                .header(EMPLOYEE_ID_HEADER, headers.get(EMPLOYEE_ID_HEADER))
                .header(HOPKINS_ID_HEADER, headers.get(HOPKINS_ID_HEADER))
                .build();
    }

    private Request buildShibRequest(Map<String, String> headers) throws MalformedURLException {
        return buildShibRequest(new Request.Builder(),
                headers, USER_SERVICE_URI, null);
    }

    private Request buildShibRequest(Map<String, String> headers, Token token) throws MalformedURLException {
        return buildShibRequest(new Request.Builder(), headers, USER_SERVICE_URI, token);
    }

    // Just make sure a body is parseable as jsonld, we really don't care what's in it, just that it has some
    // statements.
    @SuppressWarnings("resource")
    private static void assertIsjsonld(byte[] body) {
        final Model model = ModelFactory.createDefaultModel();
        model.read(new ByteArrayInputStream(body), null, "JSON-LD");
        assertTrue(new String(body), model.listStatements().toList().size() > 3);
    }
}

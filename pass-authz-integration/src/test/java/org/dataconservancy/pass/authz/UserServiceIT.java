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
import static org.junit.Assert.assertEquals;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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

    private static final String SHIB_DISPLAYNAME_HEADER = "Displayname";

    private static final String SHIB_MAIL_HEADER = "Mail";

    private static final String SHIB_EPPN_HEADER = "Eppn";

    private static final String SHIB_UNSCOPED_AFFILIATION_HEADER = "Unscoped-Affiliation";

    private static final String SHIB_SCOPED_AFFILIATION_HEADER = "Affiliation";

    private static final String SHIB_EMPLOYEE_NUMBER_HEADER = "Employeenumber";

    PassJsonAdapter json = new PassJsonAdapterBasic();

    final PassClient passClient = PassClientFactory.getPassClient();

    OkHttpClient httpClient = new OkHttpClient.Builder()
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build();

    @Test
    public void testGivenUserDoesExistReturns200() throws Exception {

        final User newUser = new User();
        newUser.setFirstName("Bugs");
        newUser.setLastName("Bunny");
        newUser.setLocalKey("10933511");
        newUser.getRoles().add(User.Role.SUBMITTER);

        final PassClient passClient = PassClientFactory.getPassClient();
        final URI id = passClient.createResource(newUser);

        attempt(60, () -> Assert.assertNotNull(passClient.findByAttribute(User.class, "localKey", "10933511")));

        final Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(SHIB_DISPLAYNAME_HEADER, "Bugs Bunny");
        shibHeaders.put(SHIB_MAIL_HEADER, "bugs@jhu.edu");
        shibHeaders.put(SHIB_EPPN_HEADER, "bbunny1@jhu.edu");
        shibHeaders.put(SHIB_UNSCOPED_AFFILIATION_HEADER, "SOCIOPATH;FACULTY");
        shibHeaders.put(SHIB_SCOPED_AFFILIATION_HEADER, "SOCIOPATH@jhu.edu;FACULTY@jhu.edu");
        shibHeaders.put(SHIB_EMPLOYEE_NUMBER_HEADER, "10933511");

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
        Assert.assertEquals("bbunny1", passUser.getInstitutionalId());
        Assert.assertEquals("Bugs Bunny", passUser.getDisplayName());
        Assert.assertEquals("bugs@jhu.edu", passUser.getEmail());
        Assert.assertEquals(passUser, fromResponse);

    }

    @Test
    public void testGivenUserDoesNotExistIsFacultyReturns200() throws Exception {

        final Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(SHIB_DISPLAYNAME_HEADER, "Daffy Duck");
        shibHeaders.put(SHIB_MAIL_HEADER, "daffy@jhu.edu");
        shibHeaders.put(SHIB_EPPN_HEADER, "dduck1@jhu.edu");
        shibHeaders.put(SHIB_UNSCOPED_AFFILIATION_HEADER, "TARGET;FACULTY");
        shibHeaders.put(SHIB_SCOPED_AFFILIATION_HEADER, "TARGET@jhu.edu;FACULTY@jhmi.edu");
        shibHeaders.put(SHIB_EMPLOYEE_NUMBER_HEADER, "10020030");

        Assert.assertNull(passClient.findByAttribute(User.class, "localKey", shibHeaders.get(
                SHIB_EMPLOYEE_NUMBER_HEADER)));

        final Request get = buildShibRequest(shibHeaders);
        final User fromResponse;
        try (Response response = httpClient.newCall(get).execute()) {
            final byte[] body = response.body().bytes();
            fromResponse = json.toModel(body, User.class);
            Assert.assertEquals(200, response.code());
            assertIsjsonld(body);
        }

        final URI id = attempt(60, () -> Optional.ofNullable(passClient.findByAttribute(User.class, "localKey",
                shibHeaders
                        .get(SHIB_EMPLOYEE_NUMBER_HEADER))).orElseThrow(() -> new NullPointerException(
                                "Did not find result from localKey search")));

        final User passUser = passClient.readResource(id, User.class);

        Assert.assertEquals(shibHeaders.get(SHIB_DISPLAYNAME_HEADER), passUser.getDisplayName());
        Assert.assertEquals(shibHeaders.get(SHIB_MAIL_HEADER), passUser.getEmail());
        Assert.assertEquals("dduck1", passUser.getInstitutionalId());
        Assert.assertEquals(passUser, fromResponse);

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
        shibHeaders.put(SHIB_DISPLAYNAME_HEADER, "Daffy Duck");
        shibHeaders.put(SHIB_MAIL_HEADER, "daffy@jhu.edu");
        shibHeaders.put(SHIB_EPPN_HEADER, "dduck1@jhu.edu");
        shibHeaders.put(SHIB_UNSCOPED_AFFILIATION_HEADER, "TARGET;STAFF");
        shibHeaders.put(SHIB_SCOPED_AFFILIATION_HEADER, "TARGET@jhu.edu;STAFF@jhmi.edu");
        shibHeaders.put(SHIB_EMPLOYEE_NUMBER_HEADER, Integer.toString(ThreadLocalRandom.current().nextInt(1000,
                99999)));

        Assert.assertNull(passClient.findByAttribute(User.class, "localKey", shibHeaders.get(
                SHIB_EMPLOYEE_NUMBER_HEADER)));

        final URI MAILTO_PLACEHOLDER = URI.create("mailto:Daffy%20Duck%20%3Cdduck%40gmail.com%3E");

        // First, add a new submission, and make it writable by someone else;
        final Submission submission = new Submission();
        submission.setSubmitter(MAILTO_PLACEHOLDER);
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
        shibHeaders.put(SHIB_DISPLAYNAME_HEADER, "Wot Gorilla");
        shibHeaders.put(SHIB_MAIL_HEADER, "gorilla@jhu.edu");
        shibHeaders.put(SHIB_EPPN_HEADER, "wotg1@jhu.edu");
        shibHeaders.put(SHIB_UNSCOPED_AFFILIATION_HEADER, "TARGET;FACULTY");
        shibHeaders.put(SHIB_SCOPED_AFFILIATION_HEADER, "TARGET@jhu.edu;FACULTY@jhmi.edu");
        shibHeaders.put(SHIB_EMPLOYEE_NUMBER_HEADER, "89248104");

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
        attempt(60, () -> {
            Assert.assertNotNull(passClient.findByAttribute(User.class, "localKey", shibHeaders.get(
                    SHIB_EMPLOYEE_NUMBER_HEADER)));
        });

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
                .header(SHIB_DISPLAYNAME_HEADER, headers.get(SHIB_DISPLAYNAME_HEADER))
                .header(SHIB_MAIL_HEADER, headers.get(SHIB_MAIL_HEADER))
                .header(SHIB_EPPN_HEADER, headers.get(SHIB_EPPN_HEADER))
                .header(SHIB_UNSCOPED_AFFILIATION_HEADER, headers.get(SHIB_UNSCOPED_AFFILIATION_HEADER))
                .header(SHIB_SCOPED_AFFILIATION_HEADER, headers.get(SHIB_SCOPED_AFFILIATION_HEADER))
                .header(SHIB_EMPLOYEE_NUMBER_HEADER, headers.get(SHIB_EMPLOYEE_NUMBER_HEADER))
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
        Assert.assertTrue(new String(body), model.listStatements().toList().size() > 3);
    }
}

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

import static java.util.Arrays.asList;
import static org.apache.http.HttpStatus.SC_CREATED;
import static org.apache.http.HttpStatus.SC_FORBIDDEN;
import static org.apache.http.HttpStatus.SC_NO_CONTENT;
import static org.apache.http.HttpStatus.SC_OK;
import static org.dataconservancy.pass.authz.JarRunner.jar;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EPPN_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.HOPKINS_ID_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.HOPKINS_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.JHED_ID_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.client.adapter.PassJsonAdapterBasic;
import org.dataconservancy.pass.model.Grant;
import org.dataconservancy.pass.model.PassEntity;
import org.dataconservancy.pass.model.Submission;
import org.dataconservancy.pass.model.SubmissionEvent;
import org.dataconservancy.pass.model.User;
import org.dataconservancy.pass.model.User.Role;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.dataconservancy.pass.model.support.Identifier;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class PolicyListenerIT extends FcrepoIT {

    static PassJsonAdapterBasic adapterBasic = new PassJsonAdapterBasic();

    static Process listnerProcess;

    static PassClient client = PassClientFactory.getPassClient();

    static User user1;

    static User user2;

    static User userAdmin;

    // We don't actually add this to the repo, this is just for convenience.
    static User BACKEND = new User();

    static final String AUTH_ROLE_HEADER = "pass-roles";

    static final URI BACKEND_ROLE = URI.create(System.getProperty("pass.backend.role"));

    static CloseableHttpClient userHttp = getAuthClient("user", "moo");

    static CloseableHttpClient http = getHttpClient();
    
    static String domain = "johnshopkins.edu";

    @BeforeClass
    public static void startListener() throws Exception {

        final AtomicBoolean ready = new AtomicBoolean(false);
        listnerProcess = jar(new File(System.getProperty("authz.listener.jar").toString()))
                .logOutput(LoggerFactory.getLogger("listener"))
                .withEnv("PASS_FEDORA_BASEURL", System.getProperty("pass.fedora.baseurl"))
                .withEnv("PASS_ELASICSEARCH_URL", System.getProperty("pass.elasticsearch.url"))
                .withEnv("PASS_FEDORA_USER", System.getProperty("pass.fedora.user"))
                .withEnv("JMS_BROKERURL", System.getProperty("jms.brokerUrl"))
                .withEnv("PASS_BACKEND_ROLE", System.getProperty("pass.backend.role"))
                .withEnv("PASS_GRANTADMIN_ROLE", System.getProperty("pass.grantadmin.role"))
                .withEnv("PASS_SUBMITTER_ROLE", System.getProperty("pass.submitter.role"))
                .withEnv("PASS_AUTHZ_QUEUE", System.getProperty("pass.authz.queue"))
                .withEnv("JMS_USERNAME", System.getProperty("jms.username"))
                .withEnv("JMS_PASSWORD", System.getProperty("jms.password"))
                .withEnv("LOG.org.dataconservancy.pass.authz", "TRACE")
                .withEnv("LOG.org.dataconservancy.pass", "DEBUG")
                .onOutputLine(s -> {
                    if (s.contains("Listening")) {
                        ready.set(true);
                    }
                })
                .start();
        attempt(30, () -> {
            if (!listnerProcess.isAlive()) {
                return;
            }
            if (!ready.get()) {
                throw new RuntimeException("Listener has not started yet");
            }
        });

        if (!listnerProcess.isAlive()) {
            throw new RuntimeException("Listener terminated");
        }

        user1 = new User();
        user1.setDisplayName("User One");
        user1.getLocatorIds().add(new Identifier(domain, EMPLOYEE_ID_TYPE,"x0001").serialize());
        user1.getLocatorIds().add(new Identifier(domain, JHED_ID_TYPE,"user1").serialize());
        user1.getLocatorIds().add(new Identifier(domain, HOPKINS_ID_TYPE, "U1U1U1").serialize());
        user1.getRoles().add(Role.SUBMITTER);
        user1 = client.createAndReadResource(user1, User.class);

        user2 = new User();
        user2.setDisplayName("User Two");
        user2.getLocatorIds().add(new Identifier(domain, EMPLOYEE_ID_TYPE,"x0002").serialize());
        user2.getLocatorIds().add(new Identifier(domain, JHED_ID_TYPE,"user2").serialize());
        user2.getLocatorIds().add(new Identifier(domain, HOPKINS_ID_TYPE, "U2U2U2").serialize());
        user2.getRoles().add(Role.SUBMITTER);
        user2 = client.createAndReadResource(user2, User.class);

        userAdmin = new User();
        userAdmin.setDisplayName("Admin user");
        userAdmin.getLocatorIds().add(new Identifier(domain, EMPLOYEE_ID_TYPE,"x0003").serialize());
        userAdmin.getLocatorIds().add(new Identifier(domain, JHED_ID_TYPE,"admin").serialize());
        userAdmin.getLocatorIds().add(new Identifier(domain, HOPKINS_ID_TYPE, "ADMIN1").serialize());
        userAdmin.getRoles().add(Role.ADMIN);
        userAdmin = client.createAndReadResource(userAdmin, User.class);

    }

    @BeforeClass
    public static void addAclContainer() throws Exception {
        final HttpPut put = new HttpPut(FCREPO_BASE_URI + System.getProperty("acl.base", "acls"));
        final HttpHead head = new HttpHead(put.getURI());

        final int code = http.execute(head, r -> {
            return r.getStatusLine().getStatusCode();
        });

        if (code == 404) {
            http.execute(put, r -> {
                assertSuccess(put.getURI(), r);
                return URI.create(r.getFirstHeader("Location").getValue());
            });
        }
    }

    @AfterClass
    public static void stopListener() {
        listnerProcess.destroy();
    }

    // Verify that a user cannot alter another user's submission
    @Test
    public void submissionOnlyEditableByCreatorTest() {
        final Grant g = new Grant();
        g.setPi(user1.getId());
        final Grant grant = client.createAndReadResource(g, Grant.class);

        // Wait until the submission is successfully created
        final Submission submission = attempt(20, () -> {
            return tryCreateSubmission(user1, grant, SC_CREATED);
        });

        // Now try modifying it as somebody else, and assure it fails.
        // Wait until the policy is enacted by the authz listener
        attempt(20, () -> {
            tryModifySubmission(user2, submission, SC_FORBIDDEN);
        });

        // Now but make sure the original submitter can still modify it.
        tryModifySubmission(user1, submission, SC_NO_CONTENT);

        // And so can the backend
        tryModifySubmission(BACKEND, submission, SC_NO_CONTENT);
    }

    // Verify that a user cannot alter a submission after it is submitted
    @Test
    public void readOnlySubmittedSubmissionTest() {
        final Grant g = new Grant();
        g.setPi(user1.getId());
        final Grant grant = client.createAndReadResource(g, Grant.class);

        // Verify that the PI can create a submission, but this time
        // set submitted=true
        final Submission submission = attempt(20, () -> {
            return tryCreateSubmission(user1, grant, SC_CREATED, true);
        });

        // Assure we cannot update the submission, since submitted=true and it should be frozen.
        // Wait until the policy is enacted by the authz listener
        attempt(20, () -> {
            tryModifySubmission(user1, submission, SC_FORBIDDEN);
        });

        // But the backend should be able to do it just fine
        tryModifySubmission(BACKEND, submission, SC_NO_CONTENT);

    }

    // Verify that a completed submission can be read by anybody
    @Test
    public void readCompleteSubmissionByEverybodyTest() {
        final Grant g = new Grant();
        g.setPi(user1.getId());
        final Grant grant = client.createAndReadResource(g, Grant.class);

        // Create a submission
        final Submission submission = attempt(20, () -> {
            return tryCreateSubmission(user1, grant, SC_CREATED, true);
        });

        // Wait until it has an ACL
        attempt(20, () -> {
            assertHasACL(submission.getId());
        });

        // Verify that the user, other submitters, grant admins, and backend can read
        tryRead(user1, submission, SC_OK);
        tryRead(user2, submission, SC_OK);
        tryRead(userAdmin, submission, SC_OK);
        tryRead(BACKEND, submission, SC_OK);
    }

    // Verify that an incomplete submission can be read by anybody
    @Test
    public void readIncompleteSubmissionByEverybodyTest() {
        final Grant g = new Grant();
        g.setPi(user1.getId());
        final Grant grant = client.createAndReadResource(g, Grant.class);

        // Create a submission
        final Submission submission = attempt(20, () -> {
            return tryCreateSubmission(user1, grant, SC_CREATED, false);
        });

        // Wait until it has an ACL
        attempt(20, () -> {
            assertHasACL(submission.getId());
        });

        // Verify that the user, other submitters, grant admins, and backend can read
        tryRead(user1, submission, SC_OK);
        tryRead(user2, submission, SC_OK);
        tryRead(userAdmin, submission, SC_OK);
        tryRead(BACKEND, submission, SC_OK);
    }

    // Verify that submissionEvents are immutable
    @Test
    public void readOnlySubmissionEventTest() {
        final SubmissionEvent event = client.createAndReadResource(new SubmissionEvent(), SubmissionEvent.class);

        // Wait until it has an ACL
        attempt(20, () -> {
            assertHasACL(event.getId());
        });

        // Verify that the user, other submitters, grant admins, and backend can read
        tryRead(user1, event, SC_OK);
        tryRead(user2, event, SC_OK);
        tryRead(userAdmin, event, SC_OK);
        tryRead(BACKEND, event, SC_OK);

        tryModifySubmissionEvent(user1, event, SC_FORBIDDEN);
        tryModifySubmissionEvent(user2, event, SC_FORBIDDEN);
        tryModifySubmissionEvent(userAdmin, event, SC_FORBIDDEN);
        tryModifySubmissionEvent(BACKEND, event, SC_FORBIDDEN);

    }

    static Submission tryCreateSubmission(User authUser, Grant grant, int expectedResponseCode,
            boolean... isSubmitted) {
        final HttpPost post = new HttpPost(URI.create(FCREPO_BASE_URI) + "submissions");
        post.setHeader("Content-Type", "application/ld+json");

        if (authUser != BACKEND) {
            post.setHeader(EMPLOYEE_ID_HEADER, getIdHeaderValueForType(authUser.getLocatorIds(), EMPLOYEE_ID_TYPE));
            post.setHeader(EPPN_HEADER, String.join("@",getIdHeaderValueForType(authUser.getLocatorIds(), JHED_ID_TYPE), domain));
            post.setHeader(HOPKINS_ID_HEADER, String.join("@",getIdHeaderValueForType(authUser.getLocatorIds(), HOPKINS_ID_TYPE), domain));
        } else {
            post.setHeader(AUTH_ROLE_HEADER, BACKEND_ROLE.toString());
        }

        final Submission submission = new Submission();
        submission.setGrants(asList(grant.getId()));
        submission.setSubmitter(authUser.getId());

        if (isSubmitted.length > 0 && isSubmitted[0]) {
            submission.setSubmitted(true);
        }

        post.setEntity(new ByteArrayEntity(adapterBasic.toJson(submission, true), ContentType.create(
                "application/ld+json")));

        try (final CloseableHttpResponse response = userHttp.execute(post)) {
            assertEquals(EntityUtils.toString(response.getEntity()), expectedResponseCode, response
                    .getStatusLine()
                    .getStatusCode());
            if (expectedResponseCode < 299) {
                return client.readResource(URI.create(response.getFirstHeader("Location").getValue()),
                        Submission.class);
            }
            return null;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    static void tryModifySubmission(User authUser, Submission submission, int expectedResponseCode) {
        submission.setMetadata(UUID.randomUUID().toString());
        doPatch(authUser, submission, expectedResponseCode);
    }

    static void tryModifySubmissionEvent(User authUser, SubmissionEvent event, int expectedResponseCode) {
        event.setComment(UUID.randomUUID().toString());
        doPatch(authUser, event, expectedResponseCode);
    }

    private static void doPatch(User authUser, PassEntity passObject, int expectedResponseCode) {
        final HttpPatch patch = new HttpPatch(passObject.getId());
        patch.setHeader("Content-Type", "application/merge-patch+json");
        if (authUser != BACKEND) {
            patch.setHeader(EMPLOYEE_ID_HEADER, getIdHeaderValueForType(authUser.getLocatorIds(), EMPLOYEE_ID_TYPE));
            patch.setHeader(EPPN_HEADER, String.join("@",getIdHeaderValueForType(authUser.getLocatorIds(), JHED_ID_TYPE), domain));
            patch.setHeader(HOPKINS_ID_HEADER, String.join("@",getIdHeaderValueForType(authUser.getLocatorIds(), HOPKINS_ID_TYPE), domain));
        } else {
            patch.setHeader(AUTH_ROLE_HEADER, BACKEND_ROLE.toString());
        }

        patch.setEntity(new ByteArrayEntity(adapterBasic.toJson(passObject, true), ContentType.create(
                "application/ld+json")));

        try (final CloseableHttpResponse response = userHttp.execute(patch)) {

            final HttpEntity entity = response.getEntity();

            final String body;
            if (entity != null) {
                body = EntityUtils.toString(entity);
            } else {
                body = "Empty response body";
            }

            assertEquals(body,
                    expectedResponseCode, response
                            .getStatusLine()
                            .getStatusCode());
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    static void tryRead(User authUser, PassEntity resource, int expectedResponseCode) {
        final HttpGet get = new HttpGet(resource.getId());
        get.setHeader("Accept", "application/ld+json");



        if (authUser != BACKEND) {
            get.setHeader(EMPLOYEE_ID_HEADER, getIdHeaderValueForType(authUser.getLocatorIds(), EMPLOYEE_ID_TYPE));
            get.setHeader(EPPN_HEADER, String.join("@",getIdHeaderValueForType(authUser.getLocatorIds(), JHED_ID_TYPE), domain));
            get.setHeader(HOPKINS_ID_HEADER, String.join("@",getIdHeaderValueForType(authUser.getLocatorIds(), HOPKINS_ID_TYPE), domain));
        } else {
            get.setHeader(AUTH_ROLE_HEADER, BACKEND_ROLE.toString());
        }

        try (final CloseableHttpResponse response = userHttp.execute(get)) {
            assertEquals(EntityUtils.toString(response.getEntity()), expectedResponseCode, response
                    .getStatusLine()
                    .getStatusCode());
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    static void assertHasACL(URI resource) {
        final HttpGet get = new HttpGet(resource);
        get.setHeader("Accept", "application/n-triples");

        try (final CloseableHttpResponse response = http.execute(get)) {
            assertTrue(EntityUtils.toString(response.getEntity()).contains("accessControl"));
        } catch (final Exception e) {
            throw new RuntimeException("ACL detection failed ", e);
        }
    }

    private static String getIdHeaderValueForType(List<String> locatorIds, String type) {
        for (String ser : locatorIds) {
            Identifier id = Identifier.deserialize(ser);
            if (id.getType().equals(type)) {
                return id.getValue();
            }
        }
        return null;
    }
}

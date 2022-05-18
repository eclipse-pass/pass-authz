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

package org.dataconservancy.pass.authz.acl;

import static java.util.Arrays.asList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.Submission;
import org.dataconservancy.pass.model.Submission.SubmissionStatus;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author apb@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class PolicyEngineTest {

    final URI ADMIN_ROLE = URI.create("http://example.org/admin");

    final URI BACKEND_ROLE = URI.create("http://example.org/backend");

    final URI SUBMITTER_ROLE = URI.create("http://example.org/submitter");

    @Mock
    ACLManager aclManager;

    @Mock
    PassClient client;

    @Mock
    ACLManager.Builder builder;

    PolicyEngine toTest;

    @Before
    public void setUp() {
        toTest = new PolicyEngine(client, aclManager);
        when(aclManager.setPermissions(any())).thenReturn(builder);
        when(builder.grantRead(any())).thenReturn(builder);
        when(builder.grantWrite(any())).thenReturn(builder);
    }

    // If the submission is in a read-only state according to its submission status, then it's read only except to
    // backend.
    @Test
    public void updateSubmissionStatusReadOnlyViaSubmissionStatusTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");

        toTest.setAdminRole(ADMIN_ROLE);
        toTest.setBackendRole(BACKEND_ROLE);
        toTest.setSubmitterRole(SUBMITTER_ROLE);

        final Submission submission = new Submission();
        submission.setSubmissionStatus(SubmissionStatus.SUBMITTED);
        when(client.readResource(eq(RESOURCE_URI), eq(Submission.class))).thenReturn(submission);

        toTest.updateSubmission(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.containsAll(asList(ADMIN_ROLE, BACKEND_ROLE,
                SUBMITTER_ROLE)) && l.size() == 3));

        verify(builder, times(1)).grantWrite(argThat(l -> l.containsAll(asList(BACKEND_ROLE)) && l.size() == 1));
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // If the submission is in a read-only state according to its 'submitted' boolean, then it's read only except to
    // backend.
    @Test
    public void updateSubmissionStatusReadOnlyViaSubmittedTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");

        toTest.setAdminRole(ADMIN_ROLE);
        toTest.setBackendRole(BACKEND_ROLE);
        toTest.setSubmitterRole(SUBMITTER_ROLE);

        final Submission submission = new Submission();
        submission.setSubmitted(true);
        when(client.readResource(eq(RESOURCE_URI), eq(Submission.class))).thenReturn(submission);

        toTest.updateSubmission(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.containsAll(asList(ADMIN_ROLE, BACKEND_ROLE,
                SUBMITTER_ROLE)) && l.size() == 3));

        verify(builder, times(1)).grantWrite(argThat(l -> l.containsAll(asList(BACKEND_ROLE)) && l.size() == 1));
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // If the submission is in a read-only state according to a cancelled status, then it's read only except to
    // backend.
    @Test
    public void updateSubmissionStatusReadOnlyViaCancelledTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");

        toTest.setAdminRole(ADMIN_ROLE);
        toTest.setBackendRole(BACKEND_ROLE);
        toTest.setSubmitterRole(SUBMITTER_ROLE);

        final Submission submission = new Submission();
        submission.setSubmissionStatus(SubmissionStatus.CANCELLED);
        when(client.readResource(eq(RESOURCE_URI), eq(Submission.class))).thenReturn(submission);

        toTest.updateSubmission(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.containsAll(asList(ADMIN_ROLE, BACKEND_ROLE,
                SUBMITTER_ROLE)) && l.size() == 3));

        verify(builder, times(1)).grantWrite(argThat(l -> l.containsAll(asList(BACKEND_ROLE)) && l.size() == 1));
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // If no roles have been defined, than a read-only submission is not writable by anybody.
    @Test
    public void updateSubmissionReadOnlyNoRolesTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");

        final Submission submission = new Submission();
        submission.setSubmitted(true);
        when(client.readResource(eq(RESOURCE_URI), eq(Submission.class))).thenReturn(submission);

        toTest.updateSubmission(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.isEmpty()));

        verify(builder, times(1)).grantWrite(argThat(l -> l.isEmpty()));
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // If the submission has been updated and it's still writable, make sure that write permissions are granted.
    @Test
    public void updateSubmissionSubmitterTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");
        final URI SUBMITTER_URI = URI.create("http://example.org/submitter");

        toTest.setAdminRole(ADMIN_ROLE);
        toTest.setBackendRole(BACKEND_ROLE);
        toTest.setSubmitterRole(SUBMITTER_ROLE);

        final Submission submission = new Submission();
        submission.setSubmissionStatus(SubmissionStatus.APPROVAL_REQUESTED);
        submission.setSubmitter(SUBMITTER_URI);
        when(client.readResource(eq(RESOURCE_URI), eq(Submission.class))).thenReturn(submission);

        toTest.updateSubmission(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.containsAll(asList(ADMIN_ROLE, BACKEND_ROLE,
                SUBMITTER_ROLE)) && l.size() == 3));

        verify(builder, times(1)).grantWrite(argThat(l -> l.containsAll(asList(BACKEND_ROLE, SUBMITTER_URI)) && l
                .size() == 2));
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // Make sure preparers are granted write permissions if the submission is writable.
    @Test
    public void updateSubmissionPreparersTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");
        final URI PREPARER_URI_1 = URI.create("http://example.org/preparer#1");
        final URI PREPARER_URI_2 = URI.create("http://example.org/preparer#2");

        toTest.setAdminRole(ADMIN_ROLE);
        toTest.setBackendRole(BACKEND_ROLE);
        toTest.setSubmitterRole(SUBMITTER_ROLE);

        final Submission submission = new Submission();
        submission.setSubmitted(false);
        submission.getPreparers().addAll(asList(PREPARER_URI_1, PREPARER_URI_2));
        when(client.readResource(eq(RESOURCE_URI), eq(Submission.class))).thenReturn(submission);

        toTest.updateSubmission(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.containsAll(asList(ADMIN_ROLE, BACKEND_ROLE,
                SUBMITTER_ROLE)) && l.size() == 3));

        verify(builder, times(1)).grantWrite(argThat(l -> l.containsAll(asList(BACKEND_ROLE, PREPARER_URI_1,
                PREPARER_URI_2)) && l
                        .size() == 3));
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // A submission with no status is writeable
    @Test
    public void submissionNoStatusTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");
        final URI SUBMITTER_URI = URI.create("http://example.org/submitter");

        toTest.setAdminRole(ADMIN_ROLE);
        toTest.setBackendRole(BACKEND_ROLE);
        toTest.setSubmitterRole(SUBMITTER_ROLE);

        final Submission submission = new Submission();
        submission.setSubmissionStatus(null);
        submission.setSubmitted(null);
        submission.setSubmitter(SUBMITTER_URI);
        when(client.readResource(eq(RESOURCE_URI), eq(Submission.class))).thenReturn(submission);

        toTest.updateSubmission(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.containsAll(asList(ADMIN_ROLE, BACKEND_ROLE,
                SUBMITTER_ROLE)) && l.size() == 3));

        verify(builder, times(1)).grantWrite(argThat(l -> l.containsAll(asList(BACKEND_ROLE, SUBMITTER_URI)) && l
                .size() == 2));
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // SubmissionEvents are immutable, grant read to all foundational roles, but no write.
    @Test
    public void submissionEventTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");

        toTest.setAdminRole(ADMIN_ROLE);
        toTest.setBackendRole(BACKEND_ROLE);
        toTest.setSubmitterRole(SUBMITTER_ROLE);

        toTest.updateSubmissionEvent(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.containsAll(asList(ADMIN_ROLE, BACKEND_ROLE,
                SUBMITTER_ROLE)) && l.size() == 3));

        verify(builder, times(0)).grantWrite(any());
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }

    // If there are no roles set, no permissions get granted
    @Test
    public void submissionEventNoRolesTest() {
        final URI RESOURCE_URI = URI.create("http://example.org/resource");

        toTest.updateSubmissionEvent(RESOURCE_URI);

        verify(aclManager).setPermissions(eq(RESOURCE_URI));
        verify(builder, times(1)).grantRead(argThat(l -> l.isEmpty()));
        verify(builder, times(0)).grantWrite(any());
        verify(builder, times(0)).grantAppend(any());

        verify(builder, times(1)).perform();
    }
}

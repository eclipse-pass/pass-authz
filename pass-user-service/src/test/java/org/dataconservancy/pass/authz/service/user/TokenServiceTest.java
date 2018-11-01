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

package org.dataconservancy.pass.authz.service.user;

import static org.dataconservancy.pass.authz.ConfigUtil.toEnvName;
import static org.dataconservancy.pass.authz.usertoken.Key.USER_TOKEN_KEY_PROPERTY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.UUID;

import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.authz.acl.ACLManager.Builder;
import org.dataconservancy.pass.authz.usertoken.BadTokenException;
import org.dataconservancy.pass.authz.usertoken.Key;
import org.dataconservancy.pass.authz.usertoken.Token;
import org.dataconservancy.pass.authz.usertoken.TokenFactory;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.PassEntity;
import org.dataconservancy.pass.model.Submission;
import org.dataconservancy.pass.model.User;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author apb@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class TokenServiceTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Mock
    PassClient passClient;

    static final Key key = Key.generate();

    TokenFactory tokenFactory = new TokenFactory(key);

    TokenService toTest;

    @Before
    public void setUp() {
        toTest = new TokenService(tokenFactory, passClient);
    }

    @Test
    public void defaultInitializationTest() {
        environmentVariables.set(toEnvName(USER_TOKEN_KEY_PROPERTY), key.toString());
        toTest = new TokenService();
        toTest.client = passClient;

        fromQueryStringValidTokenTest();
    }

    @Test
    public void fromQueryStringValidTokenTest() {

        final Token token = tokenFactory.forPassResource(randomUri()).withReference(randomUri());

        final Token fromUri = toTest.fromQueryString(token.addTo(URI.create("")).getRawQuery());

        assertEquals(token.getPassResource(), fromUri.getPassResource());
        assertEquals(token.getReference(), fromUri.getReference());
    }

    @Test
    public void fromQueryStringNoQueryStringTest() {
        assertNull(toTest.fromQueryString("http://example.org"));
    }

    @Test
    public void fromQueryStringNoTokenParamTest() {
        assertNull(toTest.fromQueryString("http://example.org/test?foo=bar"));
    }

    @Test
    public void fromQueryStringNullQueryStringTest() {
        assertNull(toTest.fromQueryString(null));
    }

    @Test(expected = BadTokenException.class)
    public void noTokenFactoryTest() {
        final TokenService nullTokenFactory = new TokenService(null, null);
        nullTokenFactory.fromQueryString("http://example.org");
    }

    @Test(expected = BadTokenException.class)
    public void malformedTokenTest() {
        toTest.fromQueryString("http://example.org/test?foo=bar&userToken=IAMABADTOKEN");
    }

    @Test
    public void insertSubmitterAndRemoveNameAndEmailTest() {

        final User toBeAssigned = new User();
        toBeAssigned.setId(randomUri());

        final Submission toBeProcessed = new Submission();
        toBeProcessed.setId(randomUri());
        toBeProcessed.setSubmitterName("The name");
        toBeProcessed.setSubmitterEmail(randomUri());

        final Token token = tokenFactory.forPassResource(toBeProcessed.getId()).withReference(toBeProcessed
                .getSubmitterEmail());

        when(passClient.readResource(eq(toBeProcessed.getId()), eq(Submission.class))).thenReturn(toBeProcessed);

        doAnswer(i -> {
            final Submission updated = i.getArgument(0);
            assertEquals(toBeAssigned.getId(), updated.getSubmitter());
            assertNull(updated.getSubmitterName());
            assertNull(updated.getSubmitterEmail());
            return null;
        }).when(passClient).updateResource(any(PassEntity.class));

        assertTrue(toTest.enactUserToken(toBeAssigned, token));

        verify(passClient, times(1)).updateResource(any(Submission.class));
    }

    @Test
    public void submitterAlreadyPresentTestTest() {

        final User alreadyAssigned = new User();
        alreadyAssigned.setId(randomUri());

        final Submission toBeProcessed = new Submission();
        toBeProcessed.setId(randomUri());
        toBeProcessed.setSubmitter(alreadyAssigned.getId());

        final Token token = tokenFactory.forPassResource(toBeProcessed.getId()).withReference(randomUri());

        when(passClient.readResource(eq(toBeProcessed.getId()), eq(Submission.class))).thenReturn(toBeProcessed);

        assertFalse(toTest.enactUserToken(alreadyAssigned, token));

        verify(passClient, times(0)).updateResource(any(Submission.class));
    }

    @Test
    public void submitterIsDefinedButDoesNotConflictWithEmailTest() {
        final User toBeAssigned = new User();
        toBeAssigned.setId(randomUri());

        final Submission toBeProcessed = new Submission();
        toBeProcessed.setId(randomUri());
        toBeProcessed.setSubmitterName("The name");
        toBeProcessed.setSubmitterEmail(randomUri());
        toBeProcessed.setSubmitter(toBeProcessed.getSubmitterEmail());

        final Token token = tokenFactory.forPassResource(toBeProcessed.getId()).withReference(toBeProcessed
                .getSubmitterEmail());

        when(passClient.readResource(eq(toBeProcessed.getId()), eq(Submission.class))).thenReturn(toBeProcessed);

        doAnswer(i -> {
            final Submission updated = i.getArgument(0);
            assertEquals(toBeAssigned.getId(), updated.getSubmitter());
            assertNull(updated.getSubmitterName());
            assertNull(updated.getSubmitterEmail());
            return null;
        }).when(passClient).updateResource(any(PassEntity.class));

        assertTrue(toTest.enactUserToken(toBeAssigned, token));

        verify(passClient, times(1)).updateResource(any(Submission.class));
    }

    @Test
    public void submitterIsDefinedButDoesNotConflictWithUserTest() {
        final User toBeAssigned = new User();
        toBeAssigned.setId(randomUri());

        final Submission toBeProcessed = new Submission();
        toBeProcessed.setId(randomUri());
        toBeProcessed.setSubmitterName("The name");
        toBeProcessed.setSubmitterEmail(randomUri());
        toBeProcessed.setSubmitter(toBeAssigned.getId());

        final Token token = tokenFactory.forPassResource(toBeProcessed.getId()).withReference(toBeProcessed
                .getSubmitterEmail());

        when(passClient.readResource(eq(toBeProcessed.getId()), eq(Submission.class))).thenReturn(toBeProcessed);

        doAnswer(i -> {
            final Submission updated = i.getArgument(0);
            assertEquals(toBeAssigned.getId(), updated.getSubmitter());
            assertNull(updated.getSubmitterName());
            assertNull(updated.getSubmitterEmail());
            return null;
        }).when(passClient).updateResource(any(PassEntity.class));

        assertTrue(toTest.enactUserToken(toBeAssigned, token));

        verify(passClient, times(1)).updateResource(any(Submission.class));
    }

    @Test
    public void conflictingSubmitterTest() {

        final User toBeAssigned = new User();
        toBeAssigned.setId(randomUri());

        final Submission toBeProcessed = new Submission();
        toBeProcessed.setId(randomUri());
        toBeProcessed.setSubmitterName("The name");
        toBeProcessed.setSubmitterEmail(randomUri());
        toBeProcessed.setSubmitter(randomUri());

        final Token token = tokenFactory.forPassResource(toBeProcessed.getId()).withReference(toBeProcessed
                .getSubmitterEmail());

        when(passClient.readResource(eq(toBeProcessed.getId()), eq(Submission.class))).thenReturn(toBeProcessed);

        try {
            toTest.enactUserToken(toBeAssigned, token);
            fail("Should have thrown an exception");
        } catch (final BadTokenException e) {
            assertTrue("Exception should mention submission ID", e.getMessage().contains(toBeProcessed.getId()
                    .toString()));
            assertTrue("Exception should mention conflicting submitter", e.getMessage().contains(toBeProcessed
                    .getSubmitter().toString()));
        }
    }

    @Test(expected = BadTokenException.class)
    public void cannotGetSubmissionTest() {

        final User illFatedUser = new User();
        illFatedUser.setId(randomUri());
        final Token token = tokenFactory.forPassResource(randomUri()).withReference(randomUri());

        when(passClient.readResource(any(URI.class), eq(Submission.class))).thenThrow(RuntimeException.class);

        toTest.enactUserToken(illFatedUser, token);
    }

    @Test(expected = BadTokenException.class)
    public void mismatchedEmailTest() {
        final User toBeAssigned = new User();
        toBeAssigned.setId(randomUri());

        final Submission toBeProcessed = new Submission();
        toBeProcessed.setId(randomUri());
        toBeProcessed.setSubmitterEmail(randomUri());

        final Token token = tokenFactory.forPassResource(toBeProcessed.getId()).withReference(randomUri());

        when(passClient.readResource(eq(toBeProcessed.getId()), eq(Submission.class))).thenReturn(toBeProcessed);

        toTest.enactUserToken(toBeAssigned, token);
    }

    @Test(expected = BadTokenException.class)
    public void nullSubmissionTest() {

        final User illFatedUser = new User();
        illFatedUser.setId(randomUri());
        final Token token = tokenFactory.forPassResource(randomUri()).withReference(randomUri());

        when(passClient.readResource(any(URI.class), eq(Submission.class))).thenReturn(null);

        toTest.enactUserToken(illFatedUser, token);
    }

    @Test(expected = NullPointerException.class)
    public void nullUserTest() {
        toTest.enactUserToken(null, mock(Token.class));
    }

    @Test(expected = NullPointerException.class)
    public void nullTokenTest() {
        toTest.enactUserToken(new User(), null);
    }

    @Test
    public void addWritePermissionsTest() {
        toTest.acls = mock(ACLManager.class);

        final User user = new User();
        user.setId(randomUri());

        final Submission submission = new Submission();
        submission.setId(randomUri());

        final Token token = mock(Token.class);
        when(token.getPassResource()).thenReturn(submission.getId());

        final Builder builder = mock(Builder.class);

        when(toTest.acls.addPermissions(eq(submission.getId()))).thenReturn(builder);
        when(builder.grantWrite(argThat(l -> {
            assertTrue("Should only grant permission to one resource; the user", l.size() == 1);
            assertTrue("Expected permission to be granted to the user.", l.contains(user.getId()));
            return true;
        }))).thenReturn(builder);
        when(builder.perform()).thenReturn(null);

        toTest.addWritePermissions(user, token);

        verify(toTest.acls, times(1)).addPermissions(eq(submission.getId()));
        verify(builder, times(1)).grantWrite(any());
        verify(builder, times(1)).perform();

    }

    private static URI randomUri() {
        return URI.create("http://example.org/" + UUID.randomUUID().toString());
    }

}

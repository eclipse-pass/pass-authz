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

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.Arrays;

import org.dataconservancy.pass.authz.acl.ACLManager;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author apb@jhu.edu
 */
public class AclManagerIT extends FcrepoIT {

    static final String AUTH_ROLE_HEADER = "pass-roles";

    static final URI AUTH_ROLE = URI.create("http://example.org/auth/myRole");

    static final URI DEFAULT_CAN_READ_ROLE = URI.create("http://example.org/auth/" + AclManagerIT.class.getName());

    // fedoraAdmin
    static CloseableHttpClient http = getHttpClient();

    // An unprivileged user
    static CloseableHttpClient userHttp = getAuthClient("user", "moo");

    static ACLManager toTest = new ACLManager();

    @BeforeClass
    public static void setDefaultRead() {
        toTest.addPermissions(URI.create(FCREPO_BASE_URI)).grantRead(asList(DEFAULT_CAN_READ_ROLE)).perform();
    }

    @Test
    public void addAndUpdateAclTest() throws Exception {
        final HttpPost post = new HttpPost(FCREPO_BASE_URI);

        final URI testObject = http.execute(post, r -> {
            assertSuccess(URI.create(FCREPO_BASE_URI), r);
            return URI.create(r.getFirstHeader("Location").getValue());
        });

        final HttpGet getTestObjectNoRole = new HttpGet(testObject);
        getTestObjectNoRole.addHeader(AUTH_ROLE_HEADER, DEFAULT_CAN_READ_ROLE.toString());

        final HttpGet getTestObjectWithRole = new HttpGet(testObject);
        getTestObjectWithRole.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        // Make sure the user can read the test object
        userHttp.execute(getTestObjectNoRole, r -> {
            assertSuccess(testObject, r, "Failed read with default role " + DEFAULT_CAN_READ_ROLE);
            return null;
        });

        // Now add the ACL
        final URI acl = toTest.addPermissions(testObject)
                .grantRead(Arrays.asList(AUTH_ROLE)).perform();

        // Make sure the user WITHOUT the proper role can NOT read the test object
        userHttp.execute(getTestObjectNoRole, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        // Make sure the user WITH the proper role CAN read the object
        userHttp.execute(getTestObjectWithRole, r -> {
            assertSuccess(testObject, r, format("Failed read by auth role <%s>", AUTH_ROLE));
            return null;
        });

        final HttpPost write = new HttpPost(testObject);
        write.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        // Make sure the user WITH the proper role can NOT write to the object,
        // as we haven't given write permissions yet.
        userHttp.execute(write, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        // Now grant the user write access.
        assertEquals(acl, toTest.addPermissions(testObject).grantWrite(Arrays.asList(AUTH_ROLE)).perform());

        // Now make sure they can write
        userHttp.execute(write, r -> {
            assertSuccess(testObject, r, format("Failed write by auth role <%s>", AUTH_ROLE));
            return null;
        });
    }

    @Test
    public void setAndUpdateAclTest() throws Exception {
        final HttpPost post = new HttpPost(FCREPO_BASE_URI);

        final URI testObject = http.execute(post, r -> {
            assertSuccess(URI.create(FCREPO_BASE_URI), r);
            return URI.create(r.getFirstHeader("Location").getValue());
        });

        final HttpGet getTestObjectNoRole = new HttpGet(testObject);
        getTestObjectNoRole.addHeader(AUTH_ROLE_HEADER, DEFAULT_CAN_READ_ROLE.toString());

        final HttpGet getTestObjectWithRole = new HttpGet(testObject);
        getTestObjectWithRole.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        // Make sure the user can read the test object
        userHttp.execute(getTestObjectNoRole, r -> {
            assertSuccess(testObject, r, "Failed read with default role " + DEFAULT_CAN_READ_ROLE);
            return null;
        });

        // Now add the ACL
        final URI acl = toTest.setPermissions(testObject)
                .grantRead(Arrays.asList(AUTH_ROLE)).perform();

        // Make sure the user WITHOUT the proper role can NOT read the test object
        userHttp.execute(getTestObjectNoRole, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        // Make sure the user WITH the proper role CAN read the object
        userHttp.execute(getTestObjectWithRole, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        final HttpPost write = new HttpPost(testObject);
        write.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        // Make sure the user WITH the proper role can NOT write to the object,
        // as we haven't given write permissions yet.
        userHttp.execute(write, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        // Now grant the user write access.
        assertEquals(acl, toTest.setPermissions(testObject)
                .grantRead(Arrays.asList(AUTH_ROLE))
                .grantWrite(Arrays.asList(AUTH_ROLE)).perform());

        // Now make sure they can write
        userHttp.execute(write, r -> {
            assertSuccess(testObject, r);
            return null;
        });
    }

    @Test
    public void addMultipleRolesTest() throws Exception {
        final URI AUTH_ROLE_2 = URI.create("http://example.org/auth/myRole2");
        final HttpPost post = new HttpPost(FCREPO_BASE_URI);

        final URI testObject = http.execute(post, r -> {
            assertSuccess(URI.create(FCREPO_BASE_URI), r);
            return URI.create(r.getFirstHeader("Location").getValue());
        });

        final HttpGet getTestObjectWithRole1 = new HttpGet(testObject);
        getTestObjectWithRole1.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        final HttpGet getTestObjectWithRole2 = new HttpGet(testObject);
        getTestObjectWithRole2.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE_2.toString());

        final HttpPost writeRole1 = new HttpPost(testObject);
        writeRole1.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        final HttpPost writeRole2 = new HttpPost(testObject);
        writeRole2.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE_2.toString());

        toTest.addPermissions(testObject).grantWrite(asList(URI.create("test:nobody"))).perform();

        // Make sure neither can read
        userHttp.execute(getTestObjectWithRole1, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        // Now grant read, write to 1 and 2.

        toTest.addPermissions(testObject)
                .grantRead(asList(AUTH_ROLE, AUTH_ROLE_2))
                .grantWrite(asList(AUTH_ROLE, AUTH_ROLE_2))
                .perform();

        // Make sure both can read and write
        userHttp.execute(getTestObjectWithRole1, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(writeRole1, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(writeRole2, r -> {
            assertSuccess(testObject, r);
            return null;
        });
    }

    @Test
    public void setMultipleRolesTest() throws Exception {
        final URI AUTH_ROLE_2 = URI.create("http://example.org/auth/myRole2");
        final HttpPost post = new HttpPost(FCREPO_BASE_URI);

        final URI testObject = http.execute(post, r -> {
            assertSuccess(URI.create(FCREPO_BASE_URI), r);
            return URI.create(r.getFirstHeader("Location").getValue());
        });

        final HttpGet getTestObjectWithRole1 = new HttpGet(testObject);
        getTestObjectWithRole1.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        final HttpGet getTestObjectWithRole2 = new HttpGet(testObject);
        getTestObjectWithRole2.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE_2.toString());

        final HttpPost writeRole1 = new HttpPost(testObject);
        writeRole1.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        final HttpPost writeRole2 = new HttpPost(testObject);
        writeRole2.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE_2.toString());

        toTest.setPermissions(testObject).grantWrite(asList(URI.create("test:nobody"))).perform();

        // Make sure neither can read
        userHttp.execute(getTestObjectWithRole1, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        // Now grant read, write to 1 and 2.

        toTest.setPermissions(testObject)
                .grantRead(asList(AUTH_ROLE, AUTH_ROLE_2))
                .grantWrite(asList(AUTH_ROLE, AUTH_ROLE_2))
                .perform();

        // Make sure both can read and write
        userHttp.execute(getTestObjectWithRole1, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(writeRole1, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(writeRole2, r -> {
            assertSuccess(testObject, r);
            return null;
        });
    }

    @Test
    public void setMultipleRolesAndRevokeTest() throws Exception {
        final URI AUTH_ROLE_2 = URI.create("http://example.org/auth/myRole2");
        final HttpPost post = new HttpPost(FCREPO_BASE_URI);

        final URI testObject = http.execute(post, r -> {
            assertSuccess(URI.create(FCREPO_BASE_URI), r);
            return URI.create(r.getFirstHeader("Location").getValue());
        });

        final HttpGet getTestObjectWithRole1 = new HttpGet(testObject);
        getTestObjectWithRole1.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        final HttpGet getTestObjectWithRole2 = new HttpGet(testObject);
        getTestObjectWithRole2.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE_2.toString());

        final HttpPost writeRole1 = new HttpPost(testObject);
        writeRole1.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        final HttpPost writeRole2 = new HttpPost(testObject);
        writeRole2.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE_2.toString());

        toTest.setPermissions(testObject).grantWrite(asList(URI.create("test:nobody"))).perform();

        // Make sure neither can read
        userHttp.execute(getTestObjectWithRole1, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            final int code = r.getStatusLine().getStatusCode();
            assertTrue(code == 401 || code == 403);
            return null;
        });

        // Now grant read to 1, and write to 2

        toTest.setPermissions(testObject)
                .grantRead(asList(AUTH_ROLE, AUTH_ROLE_2))
                .grantWrite(asList(AUTH_ROLE_2))
                .perform();

        // Make sure both can read
        userHttp.execute(getTestObjectWithRole1, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        // .. but only role 2 can write
        userHttp.execute(writeRole1, r -> {
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });

        userHttp.execute(writeRole2, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        // Now reverse the permissions
        toTest.setPermissions(testObject)
                .grantRead(asList(AUTH_ROLE, AUTH_ROLE_2))
                .grantWrite(asList(AUTH_ROLE))
                .perform();

        // Make sure both can read
        userHttp.execute(getTestObjectWithRole1, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        // .. but only role 1 can write
        userHttp.execute(writeRole1, r -> {
            assertSuccess(testObject, r);
            return null;
        });

        userHttp.execute(writeRole2, r -> {
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });

        // Now revoke everything!
        toTest.setPermissions(testObject)
                .grantRead(emptyList())
                .grantWrite(emptyList())
                .perform();

        // Make sure neither can read
        userHttp.execute(getTestObjectWithRole1, r -> {
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });
    }
}

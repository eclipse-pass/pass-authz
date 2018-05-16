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
import static org.junit.Assert.assertEquals;

import java.net.URI;
import java.util.Arrays;

import org.fcrepo.client.FcrepoClient.FcrepoClientBuilder;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author apb@jhu.edu
 */
public class AclManagerIT extends FcrepoIT {

    static final String AUTH_ROLE_HEADER = "pass-role";

    static final URI AUTH_ROLE = URI.create("http://example.org/auth/myRole");

    // fedoraAdmin
    static CloseableHttpClient http = getHttpClient();

    // An unprivileged user
    static CloseableHttpClient userHttp = getAuthClient("admin", "moo");

    ACLManager toTest = new ACLManager(new FcrepoClientBuilder().credentials("fedoraAdmin", "moo").build());

    @BeforeClass
    public static void addAclContainer() throws Exception {
        final HttpPut put = new HttpPut(FCREPO_BASE_URI + System.getProperty("acl.base", "acls"));
        final HttpHead head = new HttpHead(put.getURI());

        final int code = http.execute(head, r -> {
            return r.getStatusLine().getStatusCode();
        });

        if (code == 404) {
            http.execute(put, r -> {
                assertSuccess(r);
                return URI.create(r.getFirstHeader("Location").getValue());
            });
        }
    }

    @Test
    public void addAndUpdateAclTest() throws Exception {
        final HttpPost post = new HttpPost(FCREPO_BASE_URI);

        final URI testObject = http.execute(post, r -> {
            assertSuccess(r);
            return URI.create(r.getFirstHeader("Location").getValue());
        });

        final HttpGet getTestObjectNoRole = new HttpGet(testObject);

        final HttpGet getTestObjectWithRole = new HttpGet(testObject);
        getTestObjectWithRole.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        // Make sure the user can read the test object
        userHttp.execute(getTestObjectNoRole, r -> {
            assertSuccess(r);
            return null;
        });

        // Now add the ACL
        final URI acl = toTest.addPermissions(testObject)
                .grantRead(Arrays.asList(AUTH_ROLE)).perform();

        // Make sure the user WITHOUT the proper role can NOT read the test object
        userHttp.execute(getTestObjectNoRole, r -> {
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });

        // Make sure the user WITH the proper role CAN read the object
        userHttp.execute(getTestObjectWithRole, r -> {
            assertSuccess(r);
            return null;
        });

        final HttpPost write = new HttpPost(testObject);
        write.addHeader(AUTH_ROLE_HEADER, AUTH_ROLE.toString());

        // Make sure the user WITH the proper role can NOT write to the object,
        // as we haven't given write permissions yet.
        userHttp.execute(write, r -> {
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });

        // Now grant the user write access.
        assertEquals(acl, toTest.addPermissions(testObject).grantWrite(Arrays.asList(AUTH_ROLE)).perform());

        // Now make sure they can write
        userHttp.execute(write, r -> {
            assertSuccess(r);
            return null;
        });
    }

    @Test
    public void multipleRolesTest() throws Exception {
        final URI AUTH_ROLE_2 = URI.create("http://example.org/auth/myRole2");
        final HttpPost post = new HttpPost(FCREPO_BASE_URI);

        final URI testObject = http.execute(post, r -> {
            assertSuccess(r);
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
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            assertEquals(403, r.getStatusLine().getStatusCode());
            return null;
        });

        // Now grant read, write to 1 and 2.

        toTest.addPermissions(testObject)
                .grantRead(asList(AUTH_ROLE, AUTH_ROLE_2))
                .grantWrite(asList(AUTH_ROLE, AUTH_ROLE_2))
                .perform();

        // Make sure both can read and write
        userHttp.execute(getTestObjectWithRole1, r -> {
            assertSuccess(r);
            return null;
        });

        userHttp.execute(getTestObjectWithRole2, r -> {
            assertSuccess(r);
            return null;
        });

        userHttp.execute(writeRole1, r -> {
            assertSuccess(r);
            return null;
        });

        userHttp.execute(writeRole2, r -> {
            assertSuccess(r);
            return null;
        });

    }

}

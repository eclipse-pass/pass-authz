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

package org.dataconservancy.pass.authz.acl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.io.IOUtils.toInputStream;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.Set;

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoResponse;
import org.fcrepo.client.GetBuilder;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author apb@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class AclAnalyzerTest {

    @Mock
    FcrepoClient client;

    @Mock
    FcrepoResponse response;

    @Mock
    GetBuilder getBuilder;

    URI aclUri = URI.create("http://example.org/acl");

    URI role = URI.create("test:agent");

    @Before
    public void setUp() throws Exception {
        when(client.get(eq(aclUri))).thenReturn(getBuilder);
        when(getBuilder.accept(any())).thenReturn(getBuilder);
        when(getBuilder.preferRepresentation(any(), any())).thenReturn(getBuilder);
        when(getBuilder.perform()).thenReturn(response);
    }

    @Test
    public void getRolesTest() {
        final String ACL =
                "@prefix acl: <http://www.w3.org/ns/auth/acl#>.\n\n" +
                        "<#authorization1> \n" +
                        "a acl:Authorization; \n" +
                        "acl:agent <test:agent>; \n" +
                        "acl:accessTo <https://alice.databox.me/docs/file1>; \n" +
                        "acl:mode \n" +
                        "    acl:Read, acl:Write .\n";

        when(response.getBody()).thenReturn(toInputStream(ACL, UTF_8));

        final AclAnalyzer toTest = new AclAnalyzer(client, aclUri);

        final Set<Permission> permissions = toTest.getPermissionsforRole(role);
        assertEquals(2, permissions.size());
        assertTrue(permissions.contains(Permission.Read));
        assertTrue(permissions.contains(Permission.Write));
    }

    @Test
    public void getNoisyRolesTest() {
        final String ACL =
                "@prefix acl: <http://www.w3.org/ns/auth/acl#>.\n\n" +
                        "<#authorization1> \n" +
                        "a acl:Authorization; \n" +
                        "acl:agent <test:agent>; \n" +
                        "acl:accessTo <https://alice.databox.me/docs/file1>; \n" +
                        "acl:mode \n" +
                        "    acl:Read . \n" +
                        "<#authorization2> \n" +
                        "a acl:Authorization; \n" +
                        "acl:agent <test:agent2>; \n" +
                        "acl:accessTo <https://alice.databox.me/docs/file1>; \n" +
                        "acl:mode \n" +
                        "    acl:Read, acl:Write \n";

        when(response.getBody()).thenReturn(toInputStream(ACL, UTF_8));

        final AclAnalyzer toTest = new AclAnalyzer(client, aclUri);

        final Set<Permission> permissions = toTest.getPermissionsforRole(role);
        assertEquals(1, permissions.size());
        assertTrue(permissions.contains(Permission.Read));
    }

    @Test
    public void getAuthorizationResourceTest() {
        final String ACL =
                "@prefix acl: <http://www.w3.org/ns/auth/acl#>.\n\n" +
                        "<test:authz#authorization1> \n" +
                        "a acl:Authorization; \n" +
                        "acl:agent <test:agent>; \n" +
                        "acl:accessTo <https://alice.databox.me/docs/file1>; \n" +
                        "acl:mode \n" +
                        "    acl:Read . \n" +
                        "<test:authz#authorization2> \n" +
                        "a acl:Authorization; \n" +
                        "acl:agent <test:agent2>; \n" +
                        "acl:accessTo <https://alice.databox.me/docs/file1>; \n" +
                        "acl:mode \n" +
                        "    acl:Read, acl:Write \n";
        when(response.getBody()).thenReturn(toInputStream(ACL, UTF_8));

        final AclAnalyzer toTest = new AclAnalyzer(client, aclUri);

        final URI authzResource = toTest.getAuthorizationResourceForRole(role);
        assertEquals(URI.create("test:authz#authorization1"), authzResource);
    }

    @Test
    public void badAuthorizationResourceTest() {
        final String ACL =
                "@prefix acl: <http://www.w3.org/ns/auth/acl#>.\n\n" +
                        "<test:authz#authorization1> \n" +
                        "a acl:Authorization; \n" +
                        "acl:agent <test:agent>; \n" +
                        "acl:accessTo <https://alice.databox.me/docs/file1>; \n" +
                        "acl:mode \n" +
                        "    acl:Read . \n" +
                        "<test:authz#authorization2> \n" +
                        "a acl:Authorization; \n" +
                        "acl:agent <test:agent>; \n" +
                        "acl:accessTo <https://alice.databox.me/docs/file1>; \n" +
                        "acl:mode \n" +
                        "    acl:Read, acl:Write \n";
        when(response.getBody()).thenReturn(toInputStream(ACL, UTF_8));

        final AclAnalyzer toTest = new AclAnalyzer(client, aclUri);

        try {
            toTest.getAuthorizationResourceForRole(role);
            fail("Expected an exception when two authz resources found");
        } catch (final Exception e) {
            // expected
        }
    }

    @Test
    public void noAuthorizationResourceTest() {
        final String ACL =
                "@prefix acl: <http://www.w3.org/ns/auth/acl#>.\n\n" +
                        "<test:authz#authorization1> \n" +
                        "a acl:Authorization. \n";
        when(response.getBody()).thenReturn(toInputStream(ACL, UTF_8));

        final AclAnalyzer toTest = new AclAnalyzer(client, aclUri);

        assertNull(toTest.getAuthorizationResourceForRole(role));

    }

}

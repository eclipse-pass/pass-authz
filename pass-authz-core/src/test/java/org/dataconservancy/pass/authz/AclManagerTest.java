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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.net.URI;

import org.fcrepo.client.FcrepoClient;
import org.fcrepo.client.FcrepoResponse;
import org.fcrepo.client.GetBuilder;

import org.dataconservancy.pass.authz.ACLManager.Builder;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author apb@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class AclManagerTest {

    @Mock
    FcrepoResponse response;

    @Mock
    FcrepoClient client;

    @Mock
    GetBuilder get;

    @Test
    public void findAclTest() throws Exception {

        final URI ACL = URI.create("test:acl");

        final String RDF = "<blah> <whatever> <foo> .\n" +
                "<blah> <http://www.w3.org/ns/auth/acl#accessControl> <" + ACL + "> .\n" +
                "<blah> <whatever> \"X\"^^<Y> .\n";

        final URI RESOURCE = URI.create("test:resource");
        final ACLManager mgr = new ACLManager(client);

        final Builder builder = mgr.new Builder(RESOURCE, null);
        when(client.get(eq(RESOURCE))).thenReturn(get);
        when(get.accept("application/n-triples")).thenReturn(get);
        when(get.perform()).thenReturn(response);
        when(response.getBody()).thenReturn(IOUtils.toInputStream(RDF, UTF_8));
        when(response.getStatusCode()).thenReturn(200);

        assertEquals(ACL, builder.findOrCreateACL());
    }

}

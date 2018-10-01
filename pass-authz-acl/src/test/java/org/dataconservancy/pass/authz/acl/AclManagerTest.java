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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.dataconservancy.pass.authz.acl.ACLManager.URI_ACL_ACCESS_TO;
import static org.dataconservancy.pass.authz.acl.ACLManager.URI_ACL_AGENT;
import static org.dataconservancy.pass.authz.acl.ACLManager.URI_ACL_MODE;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.UUID;

import org.dataconservancy.pass.client.fedora.RepositoryCrawler;

import org.apache.commons.io.IOUtils;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.update.UpdateAction;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author apb@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class AclManagerTest {

    static final String ACL_MODE_READ = "http://www.w3.org/ns/auth/acl#Read";

    static final String ACL_MODE_WRITE = "http://www.w3.org/ns/auth/acl#Write";

    final URI resource = randomUri();

    final URI appendRole1 = randomUri();

    final URI appendrole2 = randomUri();

    final URI readRole1 = randomUri();

    final URI readrole2 = randomUri();

    final URI writeRole1 = randomUri();

    final URI writerole2 = randomUri();

    final URI aclContainer = randomUri();

    final URI readAuthAcl = authUri(aclContainer, Permission.Read);

    final URI writeAuthAcl = authUri(aclContainer, Permission.Write);

    @Mock
    AclDriver driver;

    @Mock
    RepositoryCrawler crawler;

    @Captor
    ArgumentCaptor<String> requestBodyCaptor;

    ACLManager toTest = new ACLManager();

    @Before
    public void setUp() {
        toTest.driver = driver;
        toTest.crawler = crawler;
        when(crawler.visit(any(), any(), any(), any())).thenReturn(0);
    }

    @Test
    public void addPermissionsEverythingExistsTest() throws Exception {

        when(driver.findOrCreateACL(eq(resource))).thenReturn(new Acl(aclContainer, false));
        when(driver.exists(authUri(aclContainer, Permission.Read))).thenReturn(true);
        when(driver.exists(authUri(aclContainer, Permission.Write))).thenReturn(true);

        toTest.addPermissions(resource)
                .grantRead(asList(readRole1, readrole2))
                .grantWrite(asList(writeRole1, writerole2))
                .grantAppend(asList(appendRole1, appendrole2)).perform();

        // First, let's look at the Read authorization

        verify(driver).patchAuthzBody(eq(readAuthAcl), requestBodyCaptor.capture());

        final Model readAuthModel = ModelFactory.createDefaultModel();
        UpdateAction.parseExecute(requestBodyCaptor.getValue(), DatasetFactory.create(readAuthModel));

        // Make sure the Read roles have read permissions
        asList(readRole1, readrole2).stream().map(URI::toString)
                .forEach(uri -> {
                    assertTrue(uri + "\n" + requestBodyCaptor.getValue(), readAuthModel.contains(
                            null,
                            readAuthModel.createProperty(URI_ACL_AGENT),
                            readAuthModel.createProperty(uri)));
                });
        assertTrue(readAuthModel.contains(
                null,
                readAuthModel.createProperty(URI_ACL_MODE),
                readAuthModel.createResource(ACL_MODE_READ)));
        assertFalse(readAuthModel.contains(
                null,
                readAuthModel.createProperty(URI_ACL_MODE),
                readAuthModel.createResource(ACL_MODE_WRITE)));
        assertTrue(readAuthModel.contains(null,
                readAuthModel.createProperty(URI_ACL_ACCESS_TO),
                readAuthModel.createResource(resource.toString())));

        // Now, let's look at the Write authorization
        verify(driver).patchAuthzBody(eq(writeAuthAcl), requestBodyCaptor.capture());

        final Model writeAuthModel = ModelFactory.createDefaultModel();
        UpdateAction.parseExecute(requestBodyCaptor.getValue(), DatasetFactory.create(writeAuthModel));

        // Make sure the append and write roles have read and write permissions
        asList(appendRole1, appendrole2, writeRole1, writerole2).stream().map(URI::toString)
                .forEach(uri -> {
                    assertTrue(uri + "\n" + requestBodyCaptor.getValue(), writeAuthModel.contains(
                            null,
                            writeAuthModel.createProperty(URI_ACL_AGENT),
                            writeAuthModel.createProperty(uri)));
                });
        assertTrue(writeAuthModel.contains(
                null,
                writeAuthModel.createProperty(URI_ACL_MODE),
                writeAuthModel.createResource(ACL_MODE_READ)));
        assertTrue(writeAuthModel.contains(
                null,
                writeAuthModel.createProperty(URI_ACL_MODE),
                writeAuthModel.createResource(ACL_MODE_WRITE)));
        assertTrue(writeAuthModel.contains(
                null,
                writeAuthModel.createProperty(URI_ACL_ACCESS_TO),
                writeAuthModel.createResource(resource.toString())));

    }

    @Test
    public void addPermissionsNoPriorAuthTest() throws Exception {

        when(driver.findOrCreateACL(eq(resource))).thenReturn(new Acl(aclContainer, true));
        when(driver.exists(authUri(aclContainer, Permission.Read))).thenReturn(false);
        when(driver.exists(authUri(aclContainer, Permission.Write))).thenReturn(false);

        toTest.addPermissions(resource)
                .grantRead(asList(readRole1, readrole2))
                .grantWrite(asList(writeRole1, writerole2))
                .grantAppend(asList(appendRole1, appendrole2)).perform();

        verify(driver, times(1)).linkAcl(aclContainer, resource);

        assertReadAclIsCorrect();
        assertWriteAclIsCorrect();
    }

    @Test
    public void setPermissionsTest() throws Exception {

        when(driver.findOrCreateACL(eq(resource))).thenReturn(new Acl(aclContainer, false));

        toTest.setPermissions(resource)
                .grantRead(asList(readRole1, readrole2))
                .grantWrite(asList(writeRole1, writerole2))
                .grantAppend(asList(appendRole1, appendrole2)).perform();

        assertReadAclIsCorrect();
        assertWriteAclIsCorrect();
    }

    @Test
    public void setPermissionsNoPriorAuthTest() throws Exception {

        when(driver.findOrCreateACL(eq(resource))).thenReturn(new Acl(aclContainer, true));

        toTest.setPermissions(resource)
                .grantRead(asList(readRole1, readrole2))
                .grantWrite(asList(writeRole1, writerole2))
                .grantAppend(asList(appendRole1, appendrole2)).perform();

        verify(driver, times(1)).linkAcl(aclContainer, resource);

        assertReadAclIsCorrect();
        assertWriteAclIsCorrect();
    }

    @Test
    public void setPermissionsUnexpectedAuthResourcesTest() throws Exception {

        final URI UNEXPECTED_AUTHX = randomUri();

        when(driver.findOrCreateACL(eq(resource))).thenReturn(new Acl(aclContainer, false));

        when(crawler.visit(eq(aclContainer), any(), any(), any())).thenAnswer(i -> {
            asList(readAuthAcl, writeAuthAcl, UNEXPECTED_AUTHX).forEach(i.getArgument(1));
            return 3;
        });

        toTest.setPermissions(resource)
                .grantRead(asList(readRole1, readrole2))
                .grantWrite(asList(writeRole1, writerole2))
                .grantAppend(asList(appendRole1, appendrole2)).perform();

        assertReadAclIsCorrect();
        assertWriteAclIsCorrect();
        verify(driver, times(1)).deleteCompletely(eq(UNEXPECTED_AUTHX));
        verify(driver, times(0)).deleteCompletely(eq(readAuthAcl));
        verify(driver, times(0)).deleteCompletely(eq(writeAuthAcl));
    }

    private void assertReadAclIsCorrect() {

        verify(driver).putAuthzBody(eq(readAuthAcl), requestBodyCaptor.capture());

        final Model readAuthModel = ModelFactory.createDefaultModel();
        readAuthModel.read(IOUtils.toInputStream(requestBodyCaptor.getValue(), UTF_8), null, "TTL");

        // Make sure the Read roles have read permissions
        asList(readRole1, readrole2).stream().map(URI::toString)
                .forEach(uri -> {
                    assertTrue(uri + "\n" + requestBodyCaptor.getValue(), readAuthModel.contains(
                            null,
                            readAuthModel.createProperty(URI_ACL_AGENT),
                            readAuthModel.createProperty(uri)));
                });
        assertTrue(readAuthModel.contains(
                null,
                readAuthModel.createProperty(URI_ACL_MODE),
                readAuthModel.createResource(ACL_MODE_READ)));
        assertFalse(readAuthModel.contains(
                null,
                readAuthModel.createProperty(URI_ACL_MODE),
                readAuthModel.createResource(ACL_MODE_WRITE)));
        assertTrue(readAuthModel.contains(null,
                readAuthModel.createProperty(URI_ACL_ACCESS_TO),
                readAuthModel.createResource(resource.toString())));
    }

    private void assertWriteAclIsCorrect() {
        // Now, let's look at the Write authorization
        verify(driver).putAuthzBody(eq(writeAuthAcl), requestBodyCaptor.capture());

        final Model writeAuthModel = ModelFactory.createDefaultModel();
        writeAuthModel.read(IOUtils.toInputStream(requestBodyCaptor.getValue(), UTF_8), null, "TTL");

        // Make sure the append and write roles have read and write permissions
        asList(appendRole1, appendrole2, writeRole1, writerole2).stream().map(URI::toString)
                .forEach(uri -> {
                    assertTrue(uri + "\n" + requestBodyCaptor.getValue(), writeAuthModel.contains(
                            null,
                            writeAuthModel.createProperty(URI_ACL_AGENT),
                            writeAuthModel.createProperty(uri)));
                });
        assertTrue(writeAuthModel.contains(
                null,
                writeAuthModel.createProperty(URI_ACL_MODE),
                writeAuthModel.createResource(ACL_MODE_READ)));
        assertTrue(writeAuthModel.contains(
                null,
                writeAuthModel.createProperty(URI_ACL_MODE),
                writeAuthModel.createResource(ACL_MODE_WRITE)));
        assertTrue(writeAuthModel.contains(
                null,
                writeAuthModel.createProperty(URI_ACL_ACCESS_TO),
                writeAuthModel.createResource(resource.toString())));
    }

    private URI randomUri() {
        return URI.create("http://example.org/random/" + UUID.randomUUID().toString() + "/");
    }

    private URI authUri(URI base, Permission permission) {
        return URI.create(base + permission.toString());
    }
}

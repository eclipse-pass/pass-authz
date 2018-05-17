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

import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.client.fedora.FedoraConfig;
import org.dataconservancy.pass.model.User;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static java.lang.Thread.sleep;

/**
 * @author apb@jhu.edu
 */
public class ShibAuthUserServiceIT extends FcrepoIT {

    private static final String SHIB_DISPLAYNAME_HEADER = "Displayname";
    private static final String SHIB_MAIL_HEADER = "Mail";
    private static final String SHIB_EPPN_HEADER = "Eppn";
    private static final String SHIB_UNSCOPED_AFFILIATION_HEADER = "Unscoped-Affiliation";
    private static final String SHIB_SCOPED_AFFILIATION_HEADER = "Affiliation";
    private static final String SHIB_EMPLOYEE_NUMBER_HEADER = "Employeenumber";

    @Test
    public void smokeTest() throws Exception {
        final PassClient client = PassClientFactory.getPassClient();

        final CloseableHttpClient http = getHttpClient();

        final User newUser = new User();
        newUser.setDisplayName("Me");

        client.createResource(newUser);

        final HttpGet get = new HttpGet(USER_SERVICE_URI);

        // For the smoke test, all we care is that the servlet is up. Don't care if it works.
        try (CloseableHttpResponse response = http.execute(get)) {
            final int code = response.getStatusLine().getStatusCode();
            if (code > 299 && code < 500) {
                throw new RuntimeException("Failed connecting to user service with " + response.getStatusLine());
            }
        }
    }

    @Ignore
    @Test
    public void testGivenUserDoesNotExistNotFacultyReturns401() throws Exception {

        Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(SHIB_DISPLAYNAME_HEADER, "Elmer Fudd");
        shibHeaders.put(SHIB_MAIL_HEADER, "elmer@jhu.edu");
        shibHeaders.put(SHIB_EPPN_HEADER, "efudd1@jhu.edu");
        shibHeaders.put(SHIB_UNSCOPED_AFFILIATION_HEADER, "HUNTER;MILLIONAIRE");
        shibHeaders.put(SHIB_SCOPED_AFFILIATION_HEADER, "HUNTER@jhu.edu;MILLIONAIRE@jhu.edu");
        shibHeaders.put(SHIB_EMPLOYEE_NUMBER_HEADER, "08675309");

        final OkHttpClient httpClient = new OkHttpClient();

        Request get = buildShibRequest(shibHeaders);
        try (Response response = httpClient.newCall(get).execute()) {
            Assert.assertEquals(401, response.code());
        }

    }

    @Ignore
    @Test
    public void testGivenUserDoesExistReturns200() throws Exception {

        User newUser = new User();
        newUser.setFirstName("Bugs");
        newUser.setLastName("Bunny");
        newUser.setLocalKey("10933511");
        newUser.getRoles().add(User.Role.SUBMITTER);

        final PassClient passClient = PassClientFactory.getPassClient();
        URI id = passClient.createResource(newUser);

        sleep(15000);

        Assert.assertNotNull(passClient.findByAttribute(User.class, "localKey", "10933511"));

        Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(SHIB_DISPLAYNAME_HEADER, "Bugs Bunny");
        shibHeaders.put(SHIB_MAIL_HEADER, "bugs@jhu.edu");
        shibHeaders.put(SHIB_EPPN_HEADER, "bbunny1@jhu.edu");
        shibHeaders.put(SHIB_UNSCOPED_AFFILIATION_HEADER, "SOCIOPATH;FACULTY");
        shibHeaders.put(SHIB_SCOPED_AFFILIATION_HEADER, "SOCIOPATH@jhu.edu;FACULTY@jhu.edu");
        shibHeaders.put(SHIB_EMPLOYEE_NUMBER_HEADER, "10933511");

        final OkHttpClient httpClient = new OkHttpClient();

        Request get = buildShibRequest(shibHeaders);
        try (Response response = httpClient.newCall(get).execute()) {
            Assert.assertEquals(200, response.code());
        }

        sleep(15000);

        User passUser = passClient.readResource(id, User.class);

        //these fields should be updated on this user
        Assert.assertEquals("bbunny1", passUser.getInstitutionalId());
        Assert.assertEquals("Bugs Bunny",passUser.getDisplayName());
        Assert.assertEquals("bugs@jhu.edu", passUser.getEmail());

    }

    @Ignore
    @Test
    public void testGivenUserDoesNotExistIsFacultyReturns200() throws Exception {

        Map<String, String> shibHeaders = new HashMap<>();
        shibHeaders.put(SHIB_DISPLAYNAME_HEADER, "Daffy Duck");
        shibHeaders.put(SHIB_MAIL_HEADER, "daffy@jhu.edu");
        shibHeaders.put(SHIB_EPPN_HEADER, "dduck1@jhu.edu");
        shibHeaders.put(SHIB_UNSCOPED_AFFILIATION_HEADER, "TARGET;FACULTY");
        shibHeaders.put(SHIB_SCOPED_AFFILIATION_HEADER, "TARGET@jhu.edu;FACULTY@jhu.edu");
        shibHeaders.put(SHIB_EMPLOYEE_NUMBER_HEADER, "10020030");

        final PassClient passClient = PassClientFactory.getPassClient();
        Assert.assertNull(passClient.findByAttribute(User.class, "localKey", shibHeaders.get(SHIB_EMPLOYEE_NUMBER_HEADER)));

        final OkHttpClient httpClient = new OkHttpClient();

        Request get = buildShibRequest(shibHeaders);
        try (Response response = httpClient.newCall(get).execute()) {
            Assert.assertEquals(200, response.code());
        }

        sleep(15000);

        URI id = passClient.findByAttribute(User.class, "localKey", shibHeaders.get(SHIB_EMPLOYEE_NUMBER_HEADER));
        User passUser = passClient.readResource(id, User.class);

        Assert.assertEquals(shibHeaders.get(SHIB_DISPLAYNAME_HEADER), passUser.getDisplayName());
        Assert.assertEquals(shibHeaders.get(SHIB_MAIL_HEADER), passUser.getEmail());
        Assert.assertEquals("dduck1", passUser.getInstitutionalId());

    }

    private Request buildShibRequest(Map<String,String> headers) throws MalformedURLException {
        String fedora_credentials = Credentials.basic(FedoraConfig.getUserName(), FedoraConfig.getPassword());
        return new Request.Builder().url(USER_SERVICE_URI.toURL())
                .header("Authorization", fedora_credentials)
                .header(SHIB_DISPLAYNAME_HEADER, headers.get(SHIB_DISPLAYNAME_HEADER))
                .header(SHIB_MAIL_HEADER, headers.get(SHIB_MAIL_HEADER))
                .header(SHIB_EPPN_HEADER, headers.get(SHIB_EPPN_HEADER))
                .header(SHIB_UNSCOPED_AFFILIATION_HEADER, headers.get(SHIB_UNSCOPED_AFFILIATION_HEADER))
                .header(SHIB_SCOPED_AFFILIATION_HEADER, headers.get(SHIB_SCOPED_AFFILIATION_HEADER))
                .header(SHIB_EMPLOYEE_NUMBER_HEADER, headers.get(SHIB_EMPLOYEE_NUMBER_HEADER))
                .build();
    }
}

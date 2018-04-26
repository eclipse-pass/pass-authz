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

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.fedora.FedoraPassClient;
import org.dataconservancy.pass.model.User;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Test;

/**
 * @author apb@jhu.edu
 */
public class ShibAuthUserServiceIT extends FcrepoIT {

    @Test
    public void smokeTest() throws Exception {
        final PassClient client = new FedoraPassClient();

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
}

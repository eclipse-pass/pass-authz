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

package org.dataconservancy.pass.authz.service.user;

import static org.dataconservancy.pass.authz.service.user.UserServlet.findLastName;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;
import org.dataconservancy.pass.client.PassClient;

import org.dataconservancy.pass.model.User;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Unit test for {@link UserServlet}
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class UserServletTest {

    private ObjectMapper mapper = new ObjectMapper();

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthUserProvider provider;

    @Mock
    PassClient client;



    @Test
    public void smokeTest() throws Exception {
        final AuthUser USER = new AuthUser();
        USER.setName("MOOO COW");
        USER.setFaculty(true);
        USER.setInstitutionalId("cowb1");
        USER.setEmail("bessie@farm.com");

        final UserServlet servlet = new UserServlet();
        servlet.provider = provider;
        servlet.fedoraClient = client;

        final StringWriter output = new StringWriter();

        when(response.getWriter()).thenReturn(new PrintWriter(output));
        when(provider.getUser(any())).thenReturn(USER);
        when(client.createResource(any())).thenReturn(URI.create("MOO"));

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(output.toString()), User.class);

        Assert.assertEquals(USER.getName(), fromServlet.getDisplayName());
        Assert.assertEquals(USER.getEmail(), fromServlet.getEmail());
        Assert.assertEquals(USER.getInstitutionalId(), fromServlet.getInstitutionalId());
    }

    @Test
    public void getLastNameTest() {

        String name1 = "Johannes Diderik van der Waals";
        String name2 = "Skip Class Jr.";
        String name3 = "Rein de Graaff";
        String name4 = "Reginald Van Gleason III";
        String name5 = "Cameron Diaz";

        String displayLast1 = "van der Waals";
        String displayLast2 = "Class";
        String displayLast3 = "de Graaff";
        String displayLast4 = "Gleason";
        String displayLast5 = "Diaz";

        Assert.assertEquals(displayLast1, findLastName(Arrays.asList(name1.split(" "))));
        Assert.assertEquals(displayLast2, findLastName(Arrays.asList(name2.split(" "))));
        Assert.assertEquals(displayLast3, findLastName(Arrays.asList(name3.split(" "))));
        Assert.assertEquals(displayLast4, findLastName(Arrays.asList(name4.split(" "))));
        Assert.assertEquals(displayLast5, findLastName(Arrays.asList(name5.split(" "))));
    }
}

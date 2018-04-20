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

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author apb@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class UserServletTest {

    ObjectMapper mapper = new ObjectMapper();

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    AuthUserProvider provider;

    @Test
    public void smokeTest() throws Exception {
        final AuthUser USER = new AuthUser();
        USER.setName("MOOO");

        final UserServlet servlet = new UserServlet();
        servlet.provider = provider;

        final StringWriter output = new StringWriter();

        when(response.getWriter()).thenReturn(new PrintWriter(output));
        when(provider.getUser(any())).thenReturn(USER);

        servlet.doGet(request, response);

        final AuthUser fromServlet = mapper.reader().treeToValue(mapper.readTree(output.toString()), AuthUser.class);

        assertEquals(USER.getName(), fromServlet.getName());
    }
}

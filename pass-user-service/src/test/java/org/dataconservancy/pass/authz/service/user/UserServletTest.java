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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Function;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;
import org.dataconservancy.pass.authz.usertoken.Key;
import org.dataconservancy.pass.authz.usertoken.TokenFactory;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.User;
import org.dataconservancy.pass.model.User.Role;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Unit test for {@link UserServlet}
 *
 * @author apb@jhu.edu
 * @author jrm@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class UserServletTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthUserProvider userProvider;

    @Mock
    PassClient client;

    @Captor
    ArgumentCaptor<User> userCaptor;

    AuthUser USER;

    ByteArrayOutputStream output;

    UserServlet servlet;

    Key key = Key.generate();

    TokenFactory tokenFactory = new TokenFactory(key);

    @Before
    public void setUp() throws Exception {
        USER = new AuthUser();

        USER.setPrincipal("bessie@farm.com");
        USER.setName("MOOO COW");
        USER.setFaculty(true);
        USER.setInstitutionalId("cowb1");
        USER.setEmail("bessie@farm.com");
        USER.setEmployeeId("08675309");

        final User user = new User();
        user.setId(URI.create("http://example.org:2020/" + UUID.randomUUID().toString()));
        user.setUsername(USER.getPrincipal());
        user.setDisplayName(USER.getName());
        user.setEmail(USER.getEmail());
        user.setInstitutionalId(USER.getInstitutionalId());
        user.setLocalKey(USER.getEmployeeId());
        user.setRoles(Arrays.asList(Role.ADMIN));
        USER.setUser(user);
        USER.setId(user.getId());
        when(client.readResource(eq(user.getId()), eq(User.class))).thenReturn(user);

        output = new ByteArrayOutputStream();

        // when(response.getWriter()).thenReturn(new PrintWriter(output));

        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {

            @Override
            public void write(int b) throws IOException {
                output.write(b);

            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
                // don't care
            }

            @Override
            public boolean isReady() {
                return true;
            }
        });

        when(userProvider.getUser(any(), any(), anyBoolean())).thenAnswer(i -> {
            final Function<AuthUser, AuthUser> criticalSection = i.getArgument(1);
            return criticalSection.apply(USER);
        });

        servlet = new UserServlet();
        servlet.tokenService = new TokenService(tokenFactory, client);
        servlet.provider = userProvider;
        servlet.fedoraClient = client;
    }

    @Test
    public void newUserTest() throws Exception {

        USER.setId(null);
        final URI newUserId = URI.create("MOO");

        // Return the User created by the user service.
        when(client.createAndReadResource(any(), eq(User.class))).thenAnswer(i -> {
            final User givenUserToCreate = i.getArgument(0);
            givenUserToCreate.setId(newUserId);
            return givenUserToCreate;
        });

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertEquals(newUserId, fromServlet.getId());
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertEquals(USER.getInstitutionalId(), fromServlet.getInstitutionalId());
        assertEquals(USER.getEmployeeId(), fromServlet.getLocalKey());

        verify(client).createAndReadResource(userCaptor.capture(), eq(User.class));

        final User created = userCaptor.getValue();
        assertEquals(USER.getName(), created.getDisplayName());
        assertEquals(USER.getInstitutionalId(), created.getInstitutionalId());
        assertEquals(USER.getEmail(), created.getEmail());
        assertEquals(USER.getEmployeeId(), created.getLocalKey());
        assertEquals(Arrays.asList(Role.SUBMITTER), created.getRoles());
    }

    @Test
    public void updateExistingUserTest() throws Exception {
        final URI foundId = URI.create("http://example.org/moo!");

        USER.setId(foundId);

        final User found = new User();
        found.setId(foundId);
        found.setLocalKey(USER.getEmployeeId());
        found.setRoles(Arrays.asList(Role.ADMIN));
        when(client.readResource(eq(foundId), eq(User.class))).thenReturn(found);

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertEquals(foundId, fromServlet.getId());
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertEquals(USER.getInstitutionalId(), fromServlet.getInstitutionalId());
        assertEquals(USER.getEmployeeId(), fromServlet.getLocalKey());

        verify(client).updateResource((userCaptor.capture()));

        final User updated = userCaptor.getValue();
        assertEquals(USER.getName(), updated.getDisplayName());
        assertEquals(USER.getInstitutionalId(), updated.getInstitutionalId());
        assertEquals(USER.getEmail(), updated.getEmail());
        assertEquals(USER.getEmployeeId(), updated.getLocalKey());
        assertEquals(Arrays.asList(Role.ADMIN), updated.getRoles());
    }

    @Test
    public void noUpdatesNeededTest() throws Exception {

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertEquals(USER.getUser().getId(), fromServlet.getId());
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertEquals(USER.getInstitutionalId(), fromServlet.getInstitutionalId());
        assertEquals(USER.getEmployeeId(), fromServlet.getLocalKey());

        verify(client, times(0)).updateResource(any());
    }

    @Test
    public void protocolSubstitutionTest() throws Exception {
        final URI foundId = URI.create("http://example.org/moo!");

        USER.setId(foundId);

        when(request.getHeader("X-Forwarded-Proto")).thenReturn("https");

        final User found = new User();
        found.setId(foundId);
        found.setUsername(USER.getPrincipal());
        found.setDisplayName(USER.getName());
        found.setEmail(USER.getEmail());
        found.setInstitutionalId(USER.getInstitutionalId());
        found.setLocalKey(USER.getEmployeeId());
        found.setRoles(Arrays.asList(Role.ADMIN));
        when(client.readResource(eq(foundId), eq(User.class))).thenReturn(found);

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertNotEquals(foundId, fromServlet.getId());
        assertTrue(fromServlet.getId().toString().contains("https"));
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertEquals(USER.getInstitutionalId(), fromServlet.getInstitutionalId());
        assertEquals(USER.getEmployeeId(), fromServlet.getLocalKey());

        verify(client, times(0)).updateResource(any());
    }

    @Test
    public void hostSubstitutionTest() throws Exception {

        when(request.getHeader("host")).thenReturn("foo.org");

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertNotEquals(USER.getId(), fromServlet.getId());
        assertTrue(fromServlet.getId().toString().startsWith("http://foo.org/"));
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertEquals(USER.getInstitutionalId(), fromServlet.getInstitutionalId());
        assertEquals(USER.getEmployeeId(), fromServlet.getLocalKey());

        verify(client, times(0)).updateResource(any());
    }

    @Test
    public void sameHostSubstitutionTest() throws Exception {

        when(request.getHeader("host")).thenReturn(USER.getId().getAuthority());

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertEquals(USER.getId(), fromServlet.getId());
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertEquals(USER.getInstitutionalId(), fromServlet.getInstitutionalId());
        assertEquals(USER.getEmployeeId(), fromServlet.getLocalKey());

        verify(client, times(0)).updateResource(any());
    }

}

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

package org.dataconservancy.pass.authz.service.user;

import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.JHED_ID_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
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
import org.dataconservancy.pass.authz.usertoken.BadTokenException;
import org.dataconservancy.pass.authz.usertoken.Token;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassJsonAdapter;
import org.dataconservancy.pass.client.adapter.PassJsonAdapterBasic;
import org.dataconservancy.pass.model.User;
import org.dataconservancy.pass.model.User.Role;

import org.dataconservancy.pass.model.support.Identifier;
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

    @Mock
    TokenService tokenService;

    @Mock
    Token token;

    @Captor
    ArgumentCaptor<User> userCaptor;

    AuthUser USER;

    ByteArrayOutputStream output;

    UserServlet servlet;

    PassJsonAdapter json = new PassJsonAdapterBasic();

    @Before
    public void setUp() throws Exception {
        String domain = "johnshopkins.edu";
        USER = new AuthUser();

        USER.setPrincipal("bessie@farm.com");
        USER.setName("MOOO COW");
        USER.setEmail("bessie@farm.com");
        USER.getLocatorIds().add(new Identifier(domain, JHED_ID_TYPE, "cowb1").serialize());
        USER.getLocatorIds().add(new Identifier(domain, EMPLOYEE_ID_TYPE, "08675309").serialize());
        USER.getLocatorIds().add(new Identifier(domain, EMPLOYEE_ID_TYPE, "P2P2P2").serialize());

        final User user = new User();
        user.setId(URI.create("http://example.org:2020/" + UUID.randomUUID().toString()));
        user.setUsername(USER.getPrincipal());
        user.setDisplayName(USER.getName());
        user.setEmail(USER.getEmail());
        user.setLocatorIds(USER.getLocatorIds());
        user.setRoles(Arrays.asList(Role.ADMIN));
        USER.setUser(user);
        USER.setId(user.getId());
        when(client.readResource(eq(user.getId()), eq(User.class))).thenReturn(user);

        output = new ByteArrayOutputStream();

        when(response.getWriter()).thenReturn(new PrintWriter(output));

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
        servlet.tokenService = tokenService;
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
        assertTrue(USER.getLocatorIds().containsAll(fromServlet.getLocatorIds()));
        assertTrue(fromServlet.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), fromServlet.getLocatorIds().size());

        verify(client).createAndReadResource(userCaptor.capture(), eq(User.class));

        final User created = userCaptor.getValue();
        assertEquals(USER.getName(), created.getDisplayName());
        assertEquals(USER.getEmail(), created.getEmail());
        assertEquals(Arrays.asList(Role.SUBMITTER), created.getRoles());
        assertTrue(USER.getLocatorIds().containsAll(created.getLocatorIds()));
        assertTrue(created.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), created.getLocatorIds().size());

        verify(response, times(1)).setStatus(eq(200));
        assertOutputEquals(created);
    }

    @Test
    public void updateExistingUserTest() throws Exception {
        final URI foundId = URI.create("http://example.org/moo!");

        USER.setId(foundId);

        final User found = new User();
        found.setId(foundId);
        found.setLocatorIds(USER.getLocatorIds());
        found.setRoles(Arrays.asList(Role.ADMIN));
        when(client.readResource(eq(foundId), eq(User.class))).thenReturn(found);
        when(client.updateAndReadResource(argThat(u -> u.getId().equals(foundId)), eq(User.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertEquals(foundId, fromServlet.getId());
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertTrue(USER.getLocatorIds().containsAll(fromServlet.getLocatorIds()));
        assertTrue(fromServlet.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), fromServlet.getLocatorIds().size());

        verify(client).readResource(eq(foundId), eq(User.class));
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(client).updateAndReadResource(userCaptor.capture(), eq(User.class));
        assertEquals(foundId, userCaptor.getValue().getId());

        final User updated = userCaptor.getValue();
        assertEquals(USER.getName(), updated.getDisplayName());
        assertEquals(USER.getEmail(), updated.getEmail());
        assertEquals(Arrays.asList(Role.ADMIN), updated.getRoles());
        assertTrue(USER.getLocatorIds().containsAll(updated.getLocatorIds()));
        assertTrue(updated.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), updated.getLocatorIds().size());

        verify(response, times(1)).setStatus(eq(200));
        assertOutputEquals(updated);
    }

    @Test
    public void noUpdatesNeededTest() throws Exception {

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertEquals(USER.getUser().getId(), fromServlet.getId());
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertTrue(USER.getLocatorIds().containsAll(fromServlet.getLocatorIds()));
        assertTrue(fromServlet.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), fromServlet.getLocatorIds().size());

        verify(client, times(0)).updateResource(any());

        verify(response, times(1)).setStatus(eq(200));
        assertOutputEquals(USER.getUser());
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
        found.setLocatorIds(USER.getLocatorIds());
        found.setRoles(Arrays.asList(Role.ADMIN));
        when(client.readResource(eq(foundId), eq(User.class))).thenReturn(found);

        servlet.doGet(request, response);

        final User fromServlet = mapper.reader().treeToValue(mapper.readTree(new String(output.toByteArray())),
                User.class);

        assertNotEquals(foundId, fromServlet.getId());
        assertTrue(fromServlet.getId().toString().contains("https"));
        assertEquals(USER.getName(), fromServlet.getDisplayName());
        assertEquals(USER.getEmail(), fromServlet.getEmail());
        assertTrue(USER.getLocatorIds().containsAll(fromServlet.getLocatorIds()));
        assertTrue(fromServlet.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), fromServlet.getLocatorIds().size());

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
        assertTrue(USER.getLocatorIds().containsAll(fromServlet.getLocatorIds()));
        assertTrue(fromServlet.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), fromServlet.getLocatorIds().size());

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
        assertTrue(USER.getLocatorIds().containsAll(fromServlet.getLocatorIds()));
        assertTrue(fromServlet.getLocatorIds().containsAll(USER.getLocatorIds()));
        assertEquals(USER.getLocatorIds().size(), fromServlet.getLocatorIds().size());
        verify(client, times(0)).updateResource(any());
    }

    @Test
    public void invalidUserTest() throws Exception {

        final AuthUser unauthorizedUser = new AuthUser();
        unauthorizedUser.setId(null);
        final AuthUserProvider noUserProvider = mock(AuthUserProvider.class);
        when(noUserProvider.getUser(any(), any(), anyBoolean())).thenReturn(unauthorizedUser);
        servlet.provider = noUserProvider;
        servlet.doGet(request, response);

        verify(response, times(1)).setStatus(eq(401));
    }

    @Test
    public void noTokenTest() throws Exception {
        servlet.doGet(request, response);
        verify(tokenService, times(0)).enactUserToken(any(User.class), any(Token.class));
        verify(response, times(1)).setStatus(eq(200));
        assertOutputEquals(USER.getUser());
    }

    @Test
    public void badTokenTest() throws Exception {
        final String queryString = "userToken=BLAH";
        when(request.getQueryString()).thenReturn(queryString);
        when(tokenService.fromQueryString(eq(queryString))).thenReturn(token);
        when(tokenService.enactUserToken(any(), any())).thenThrow(BadTokenException.class);

        servlet.doGet(request, response);
        verify(response, times(1)).setStatus(eq(400));
    }

    @Test
    public void tokenApplicationTest() throws Exception {
        final String queryString = "userToken=BLAH";
        when(request.getQueryString()).thenReturn(queryString);
        when(tokenService.fromQueryString(eq(queryString))).thenReturn(token);
        when(tokenService.enactUserToken(eq(USER.getUser()), eq(token))).thenReturn(true);

        servlet.doGet(request, response);
        verify(tokenService, times(1)).enactUserToken(eq(USER.getUser()), eq(token));
        verify(tokenService, times(1)).addWritePermissions(eq(USER.getUser()), eq(token));
        verify(response, times(1)).setStatus(eq(200));
        assertOutputEquals(USER.getUser());
    }

    @Test
    public void tokenApplicationNewUserTest() throws Exception {
        final String queryString = "userToken=BLAH";
        USER.setId(null);
        final URI newUserId = URI.create("MOO");

        // Return the User created by the user service.
        when(client.createAndReadResource(any(), eq(User.class))).thenAnswer(i -> {
            final User givenUserToCreate = i.getArgument(0);
            givenUserToCreate.setId(newUserId);
            return givenUserToCreate;
        });

        when(request.getQueryString()).thenReturn(queryString);
        when(tokenService.fromQueryString(eq(queryString))).thenReturn(token);
        when(tokenService.enactUserToken(any(User.class), eq(token))).thenReturn(true);

        servlet.doGet(request, response);
        verify(tokenService, times(1)).enactUserToken(any(User.class), eq(token));
        verify(tokenService, times(1)).addWritePermissions(any(User.class), eq(token));
        verify(response, times(1)).setStatus(eq(200));

        USER.getUser().setId(newUserId);
        assertOutputEquals(USER.getUser());
    }

    @Test
    public void tokenAllreadyAppliedTest() throws Exception {
        final String queryString = "userToken=BLAH";
        when(request.getQueryString()).thenReturn(queryString);
        when(tokenService.fromQueryString(eq(queryString))).thenReturn(token);
        when(tokenService.enactUserToken(eq(USER.getUser()), eq(token))).thenReturn(false);

        servlet.doGet(request, response);
        verify(tokenService, times(1)).enactUserToken(eq(USER.getUser()), eq(token));
        verify(tokenService, times(0)).addWritePermissions(any(), any());
        verify(response, times(1)).setStatus(eq(200));
        assertOutputEquals(USER.getUser());
    }

    private void assertOutputEquals(User user) {
        final User fromOut = json.toModel(output.toByteArray(), User.class);
        fromOut.setContext(user.getContext());
        assertEquals(user, fromOut);
    }

}

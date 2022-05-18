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

package org.dataconservancy.pass.authz.roles;

import static java.util.Collections.emptySet;
import static org.dataconservancy.pass.authz.roles.AuthRolesProvider.getRoles;
import static org.dataconservancy.pass.authz.roles.PassRolesFilter.PROP_ALLOW_EXTERNAL_ROLES;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.model.User;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * @author apb@jhu.edu
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(value = { AuthRolesProvider.class, PassClientFactory.class })
public class PassRolesFilterTest {

    @Mock
    HttpServletRequest request;

    @Mock
    ServletContext servletContext;

    @Mock
    HttpServletResponse response;

    @Mock
    AuthUserProvider userProvider;

    @Mock
    PassClient passClient;

    @Mock
    FilterChain chain;

    @Captor
    ArgumentCaptor<HttpServletRequest> requestCaptor;

    AuthUser authUser;

    Set<URI> roles;

    PassRolesFilter toTest;

    @Before
    public void setUp() {
        System.setProperty(PROP_ALLOW_EXTERNAL_ROLES, "false");
        roles = new HashSet<>();
        authUser = new AuthUser();

        // Static mocks
        mockStatic(AuthRolesProvider.class);
        mockStatic(PassClientFactory.class);
        when(PassClientFactory.getPassClient()).thenReturn(passClient);
        when(getRoles(eq(authUser))).thenReturn(roles);

        toTest = new PassRolesFilter();

        when(request.getServletContext()).thenReturn(servletContext);
        when(servletContext.getContext(any())).thenReturn(servletContext);
        when(servletContext.getAttribute(any())).thenReturn(userProvider);
        when(request.getRequestURI()).thenReturn("/fcrepo/rest/whatever");

        when(userProvider.getUser(any(), any(), eq(true))).thenReturn(authUser);
    }

    @Test
    public void removeExternalAuthzTest() throws Exception {
        System.setProperty(PROP_ALLOW_EXTERNAL_ROLES, "false");
        toTest.init(null);

        when(request.getHeader(toTest.authzHeader)).thenReturn("foo");

        toTest.doFilter(request, response, chain);

        verify(chain).doFilter(requestCaptor.capture(), eq(response));

        assertEquals("", requestCaptor.getValue().getHeader(toTest.authzHeader));
        verify(response, times(0)).sendError(eq(500), any());

    }

    @Test
    public void acceptExternalAuthzTest() throws Exception {
        final String AUTHZ_VALUE = "foo";

        System.setProperty(PROP_ALLOW_EXTERNAL_ROLES, "true");
        toTest.init(null);

        when(request.getHeader(toTest.authzHeader)).thenReturn(AUTHZ_VALUE);

        toTest.doFilter(request, response, chain);

        verify(chain).doFilter(requestCaptor.capture(), eq(response));

        assertEquals(AUTHZ_VALUE, requestCaptor.getValue().getHeader(toTest.authzHeader));
        verify(response, times(0)).sendError(eq(500), any());
    }

    @Test
    public void mergeExternalAuthzTest() throws Exception {
        final String INTERNAL_AUTHZ_VALUE = "foo";
        final String EXTERNAL_AUTHZ_VALUE = "bar";
        System.setProperty(PROP_ALLOW_EXTERNAL_ROLES, "true");
        toTest.init(null);

        when(request.getHeader(toTest.authzHeader)).thenReturn(EXTERNAL_AUTHZ_VALUE);
        roles.add(URI.create(INTERNAL_AUTHZ_VALUE));

        toTest.doFilter(request, response, chain);
        verify(chain).doFilter(requestCaptor.capture(), eq(response));

        final String authzHeader = requestCaptor.getValue().getHeader(toTest.authzHeader);
        final List<String> observedRoles = Arrays.asList(authzHeader.split(toTest.authzRoleSeparator));

        assertEquals(2, observedRoles.size());
        assertTrue(observedRoles.contains(INTERNAL_AUTHZ_VALUE));
        assertTrue(observedRoles.contains(EXTERNAL_AUTHZ_VALUE));
    }

    @Test
    public void basicRolesTest() throws Exception {
        final String AUTHZ_VALUE_1 = "foo";
        final String AUTHZ_VALUE_2 = "bar";

        roles.addAll(Arrays.asList(URI.create(AUTHZ_VALUE_1), URI.create(AUTHZ_VALUE_2)));

        toTest.init(null);

        toTest.doFilter(request, response, chain);
        verify(chain).doFilter(requestCaptor.capture(), eq(response));

        final String authzHeader = requestCaptor.getValue().getHeader(toTest.authzHeader);
        final List<String> observedRoles = Arrays.asList(authzHeader.split(toTest.authzRoleSeparator));

        assertEquals(observedRoles.toString(), 2, observedRoles.size());
        assertTrue(observedRoles.contains(AUTHZ_VALUE_1));
        assertTrue(observedRoles.contains(AUTHZ_VALUE_2));

        verify(response, times(0)).sendError(eq(500), any());
    }

    @Test
    public void noUserServiceConxtextTest() throws Exception {
        when(servletContext.getContext(any())).thenReturn(null);
        toTest.init(null);

        try {
            toTest.doFilter(request, response, chain);
            verify(response).sendError(eq(500), any());
        } catch (final Exception e) {
            fail("Should not have thrown an exception");
        }
    }

    @Test
    public void noAuthRolesFilterTest() throws Exception {
        when(servletContext.getAttribute(any())).thenReturn(null);
        toTest.init(null);

        try {
            toTest.doFilter(request, response, chain);
            verify(response).sendError(eq(500), any());
        } catch (final Exception e) {
            fail("Should not have thrown an exception");
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void nullUserTest() throws Exception {

        final URI id = URI.create("http://example.org/nullUser");
        authUser.setId(id);
        authUser.setUser(null);

        final User user = new User();
        user.setId(id);
        user.setEmail("moo@cow.example.org");

        final AtomicReference<AuthUser> capturedAuthUser = new AtomicReference<AuthUser>(null);

        when(passClient.readResource(eq(id), eq(User.class))).thenReturn(user);
        when(getRoles(any())).thenAnswer(i -> {
            capturedAuthUser.set(i.getArgument(0));
            return emptySet();
        });

        when(userProvider.getUser(any(), any(), eq(true))).thenAnswer(i -> {
            System.err.println(i.getArgument(1).toString());
            return ((Function<AuthUser, AuthUser>) i.getArgument(1)).apply(authUser);
        });

        toTest.init(null);
        toTest.doFilter(request, response, chain);

        verify(passClient, times(1)).readResource(eq(id), eq(User.class));
        assertNotNull(authUser.getUser());
        assertEquals(user, authUser.getUser());
        assertEquals(user, capturedAuthUser.get().getUser());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void nonNullUserTest() throws Exception {
        final URI id = URI.create("http://example.org/nullUser");
        final User user = new User();
        user.setId(id);
        user.setEmail("moo@cow.example.org");
        authUser.setId(id);
        authUser.setUser(user);

        final AtomicReference<AuthUser> capturedAuthUser = new AtomicReference<AuthUser>(null);

        when(passClient.readResource(eq(id), eq(User.class))).thenReturn(user);
        when(getRoles(any())).thenAnswer(i -> {
            capturedAuthUser.set(i.getArgument(0));
            return emptySet();
        });

        when(userProvider.getUser(any(), any(), eq(true))).thenAnswer(i -> {
            System.err.println(i.getArgument(1).toString());
            return ((Function<AuthUser, AuthUser>) i.getArgument(1)).apply(authUser);
        });

        toTest.init(null);
        toTest.doFilter(request, response, chain);

        verify(passClient, times(0)).readResource(eq(id), eq(User.class));
        assertNotNull(authUser.getUser());
        assertEquals(user, authUser.getUser());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void noUserTest() throws Exception {
        final URI id = URI.create("http://example.org/nullUser");
        final User user = new User();
        user.setId(id);
        user.setEmail("moo@cow.example.org");
        authUser.setId(id);
        authUser.setUser(null);

        final AtomicReference<AuthUser> capturedAuthUser = new AtomicReference<AuthUser>(null);

        when(passClient.readResource(eq(id), eq(User.class))).thenReturn(null);
        when(getRoles(any())).thenAnswer(i -> {
            capturedAuthUser.set(i.getArgument(0));
            return emptySet();
        });

        when(userProvider.getUser(any(), any(), eq(true))).thenAnswer(i -> {
            System.err.println(i.getArgument(1).toString());
            return ((Function<AuthUser, AuthUser>) i.getArgument(1)).apply(authUser);
        });

        toTest.init(null);
        toTest.doFilter(request, response, chain);

        verify(passClient, times(1)).readResource(eq(id), eq(User.class));
        assertNull(authUser.getUser());
    }
}

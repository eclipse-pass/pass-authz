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

package org.dataconservancy.pass.authz.filter;

import static org.dataconservancy.pass.authz.filter.PassRolesFilter.PROP_ALLOW_EXTERNAL_ROLES;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dataconservancy.pass.authz.AuthRolesProvider;
import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.authz.AuthUserProvider;

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
public class PassRolesFilterTest {

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    AuthUserProvider userProvider;

    @Mock
    AuthRolesProvider rolesProvider;

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
        toTest = new PassRolesFilter();
        toTest.rolesProvider = rolesProvider;
        toTest.userProvider = userProvider;

        when(userProvider.getUser(any(HttpServletRequest.class))).thenReturn(authUser);
        when(rolesProvider.getRoles(eq(authUser))).thenReturn(roles);
    }

    @Test
    public void removeExternalAuthzTest() throws Exception {
        System.setProperty(PROP_ALLOW_EXTERNAL_ROLES, "false");
        toTest.init(null);

        when(request.getHeader(toTest.authzHeader)).thenReturn("foo");

        toTest.doFilter(request, response, chain);

        verify(chain).doFilter(requestCaptor.capture(), eq(response));

        assertEquals("", requestCaptor.getValue().getHeader(toTest.authzHeader));

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

        assertEquals(2, observedRoles.size());
        assertTrue(observedRoles.contains(AUTHZ_VALUE_1));
        assertTrue(observedRoles.contains(AUTHZ_VALUE_2));
    }
}

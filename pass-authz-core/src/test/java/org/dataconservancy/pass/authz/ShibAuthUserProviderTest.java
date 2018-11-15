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

package org.dataconservancy.pass.authz;

import static java.util.Arrays.asList;


import static org.dataconservancy.pass.authz.ShibAuthUserProvider.DISPLAY_NAME_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMAIL_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EPPN_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.HOPKINS_ID_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.HOPKINS_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.JHED_ID_TYPE;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.SCOPED_AFFILIATION_HEADER;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.UUID;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.User;

import org.dataconservancy.pass.model.support.Identifier;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.RestoreSystemProperties;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author jrm@jhu.edu
 */
@RunWith(MockitoJUnitRunner.Silent.class)
public class ShibAuthUserProviderTest {

    @Rule
    public final RestoreSystemProperties r = new RestoreSystemProperties();

    @Mock
    private HttpServletRequest request;

    @Mock
    private PassClient client;

    @Mock
    ExpiringLRUCache<String, AuthUser> mockCache;

    @Mock
    Function<AuthUser, AuthUser> doAfter;

    @Before
    public void allowShibHeaders() {
        System.setProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS, "true");
    }

    String DOMAIN = "johnshopkins.edu";

    @Test
    public void getFacultyUserTest() {

        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@johnshopkins.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "TTT777@johnshopkins.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID_HEADER)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID_HEADER)).thenReturn(hopkinsId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);

        final AuthUser user = underTest.getUser(request);

        String jhedId = new Identifier(DOMAIN, JHED_ID_TYPE, "bcow666").serialize();
        String eeId = new Identifier(DOMAIN, EMPLOYEE_ID_TYPE, "12345678").serialize();
        String hkId = new Identifier(DOMAIN, HOPKINS_ID_TYPE, "TTT777").serialize();
        assertEquals(displayName, user.getName());
        assertEquals(emailAddress, user.getEmail());
        assertTrue(user.getLocatorIds().contains(jhedId));
        assertTrue(user.getLocatorIds().contains(eeId));
        assertTrue(user.getLocatorIds().contains(hkId));
    }

    @Test
    public void getNonFacultyUserTest() {

        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@johnshopkins.edu";
        final String employeeId = "87654321";
        final String hopkinsId = "H6H6H6@johnshopkins.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID_HEADER)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID_HEADER)).thenReturn(hopkinsId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);

        String jhedId = new Identifier(DOMAIN, JHED_ID_TYPE, "cbull999").serialize();
        String eeId = new Identifier(DOMAIN, EMPLOYEE_ID_TYPE, "87654321").serialize();

        assertEquals(displayName, user.getName());
        assertEquals(emailAddress, user.getEmail());
        assertTrue(user.getLocatorIds().contains(jhedId));
        assertTrue(user.getLocatorIds().contains(eeId));
    }

    @Test
    public void userPrincipalTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        Assert.assertEquals(eppn, user.getPrincipal());
    }

    @Test
    public void domainTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@johnshopkins.edu";
        final String scopedAffiliation = "STAFF@bovidae.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(3, user.getDomains().size());
        assertTrue(user.getDomains().containsAll(asList("bovidae.edu", "library.jhu.edu", "johnshopkins.edu")));
        assertFalse(user.getDomains().contains("rodeo.org"));
    }

    // Everything should simply be null if there are no shib headers.
    @Test
    public void noShibHeadersTest() {
        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        assertNull(user.getId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
        assertEquals(0, user.getLocatorIds().size());
    }

    @Test
    public void attributeTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@johnshopkins.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getAttribute(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getAttribute(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getAttribute(EPPN_HEADER)).thenReturn(eppn);
        when(request.getAttribute(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(3, user.getDomains().size());
        assertTrue(user.getDomains().containsAll(asList("jhu.edu","johnshopkins.edu", "library.jhu.edu")));
    }

    @Test
    public void attributePreferenceTest() {
        final String displayNameAttr = "Charlie Bull";
        final String displayNameHeader = "Charlie Horn";
        final String eppn = "cbull999@johnshopkins.edu";

        when(request.getAttribute(DISPLAY_NAME_HEADER)).thenReturn(displayNameAttr);
        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayNameHeader);
        when(request.getAttribute(EPPN_HEADER)).thenReturn(eppn);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(displayNameAttr, user.getName());
    }

    @Test
    public void noShibHeadersByDefaultTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@johnshopkins.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        System.clearProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        assertNull(user.getId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
        assertEquals(0, user.getLocatorIds().size());
    }

    @Test
    public void noShibHeadersIfExplicitlyFalseTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@johnshopkins.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        System.setProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS, "false");

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        assertNull(user.getId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
        assertEquals(0, user.getLocatorIds().size());
    }

    @Test
    public void errorFromCacheGetTest() {

        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@johnshopkins.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "A1A1A1@johnshopkins.edu";
        String cacheLookupId = new Identifier(DOMAIN, HOPKINS_ID_TYPE, "A1A1A1").serialize();

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID_HEADER)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID_HEADER)).thenReturn(hopkinsId);

        final RuntimeException theException = new RuntimeException();

        when(mockCache.getOrDo(eq(cacheLookupId), any(), any())).thenThrow(theException);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client, mockCache);

        try {
            underTest.getUser(request);
            fail("Should have thrown an exception!");
        } catch (final Exception e) {
            assertEquals(theException, e.getCause());
        }
    }

    @Test
    public void filterAddsUserTest() {
        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@johnshopkins.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "D2D2D2@johnshopkins.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID_HEADER)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID_HEADER)).thenReturn(hopkinsId);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        final User foundUser = new User();

        when(doAfter.apply(any())).thenAnswer(i -> {
            final AuthUser u = i.getArgument(0);
            u.setUser(foundUser);
            return u;
        });
        String cacheLookupId = new Identifier(DOMAIN, HOPKINS_ID_TYPE, "D2D2D2").serialize();
        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser authUser = underTest.getUser(request, doAfter, true);
        assertNotNull(underTest.userCache.get(cacheLookupId));

        assertEquals(foundUser, authUser.getUser());
    }

    @Test
    public void filterDoesNotAddUserTest() {
        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@johnshopkins.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        final String employeeId = "12345678";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID_HEADER)).thenReturn(employeeId);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        when(doAfter.apply(any())).thenAnswer(i -> {
            final AuthUser u = i.getArgument(0);
            return u;
        });

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser authUser = underTest.getUser(request, doAfter, true);
        assertNotNull(authUser);
        assertNull(underTest.userCache.get(employeeId));
    }

}

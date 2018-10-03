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
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMPLOYEE_ID;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.HOPKINS_ID;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EPPN_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.SCOPED_AFFILIATION_HEADER;
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

import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.User;

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
    ExpiringLRUCache<String, User> mockCache;

    @Mock
    Function<AuthUser, AuthUser> doAfter;

    @Before
    public void allowShibHeaders() {
        System.setProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS, "true");
    }

    @Test
    public void getFacultyUserTest() {

        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@jhu.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "A1B2C3";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);

        final AuthUser user = underTest.getUser(request);

        assertEquals(displayName, user.getName());
        assertTrue(user.getLocatorIds().contains("johnshopkins.edu:jhed:bcow666"));
        assertTrue(user.getLocatorIds().contains("johnshopkins.edu:employeeid:"+employeeId));
        assertTrue(user.getLocatorIds().contains("johnshopkins.edu:hopkinsid:"+hopkinsId));
        assertEquals(emailAddress, user.getEmail());
    }

    @Test
    public void getNonFacultyUserTest() {

        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String employeeId = "87654321";
        final String hopkinsId = "AA22BB";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(displayName, user.getName());
        assertTrue(user.getLocatorIds().contains("johnshopkins.edu:jhed:cbull999"));
        assertTrue(user.getLocatorIds().contains("johnshopkins.edu:employeeid:"+employeeId));

        assertEquals(emailAddress, user.getEmail());
    }

    @Test
    public void userPrincipalTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String hopkinsId = "ZZZT0P";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(eppn, user.getPrincipal());
    }

    @Test
    public void domainTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";
        final String hopkinsId = "ZZZT0P";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(2, user.getDomains().size());
        assertTrue(user.getDomains().containsAll(asList("jhu.edu", "library.jhu.edu")));
    }

    // Everything should simply be null if there are no shib headers.
    @Test
    public void noShibHeadersTest() {
        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        assertEquals(0, user.getLocatorIds().size());
        assertNull(user.getId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
    }

    @Test
    public void attributeTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";
        final String hopkinsId = "ZZZT0P";

        when(request.getAttribute(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getAttribute(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getAttribute(EPPN_HEADER)).thenReturn(eppn);
        when(request.getAttribute(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(2, user.getDomains().size());
        assertTrue(user.getDomains().containsAll(asList("jhu.edu", "library.jhu.edu")));
    }

    @Test
    public void attributePreferenceTest() {
        final String displayNameAttr = "Charlie Bull";
        final String displayNameHeader = "Charlie Horn";

        when(request.getAttribute(DISPLAY_NAME_HEADER)).thenReturn(displayNameAttr);
        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayNameHeader);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(displayNameAttr, user.getName());
    }

    @Test
    public void noShibHeadersByDefaultTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";
        final String hopkinsId = "ZZZT0P";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        System.clearProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        //assertNull(user.getEmployeeId());
        assertNull(user.getId());
        //assertNull(user.getInstitutionalId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
    }

    @Test
    public void noShibHeadersIfExplicitlyFalseTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";
        final String hopkinsId = "ZZZT0P";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        System.setProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS, "false");

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        //assertNull(user.getEmployeeId());
        assertNull(user.getId());
        //assertNull(user.getInstitutionalId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
    }

    @Test
    public void errorFromCacheGetTest() {

        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@jhu.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "A1B2C3";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        final RuntimeException theException = new RuntimeException();

        when(mockCache.getOrDo(eq("johnshopkins.edu:hopkinsid:A1B2C3"), any())).thenThrow(theException);

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
        final String eppn = "bcow666@jhu.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "A1B2C3";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        final User foundUser = new User();

        when(doAfter.apply(any())).thenAnswer(i -> {
            final AuthUser u = i.getArgument(0);
            u.setId(u.getId());
            u.setUser(foundUser);
            return u;
        });

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser authUser = underTest.getUser(request, doAfter, true);
        assertNotNull(underTest.userCache.get("johnshopkins.edu:hopkinsid:A1B2C3"));

        assertEquals(foundUser, authUser.getUser());
    }

    @Test
    public void filterDoesNotAddUserTest() {
        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@jhu.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "A1B2C3";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        when(doAfter.apply(any())).thenAnswer(i -> {
            final AuthUser u = i.getArgument(0);
            return u;
        });

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser authUser = underTest.getUser(request, doAfter, true);
        assertNotNull(authUser);
        assertNull(underTest.userCache.get("johnshopkins.edu:hopkinsid:A1B2C3"));
    }

    @Test
    public void forceComputationTest() {
        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@jhu.edu";
        final String employeeId = "12345678";
        final String hopkinsId = "A1B2C3";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);
        when(request.getHeader(HOPKINS_ID)).thenReturn(hopkinsId);

        when(doAfter.apply(any())).thenAnswer(i -> {
            final AuthUser u = i.getArgument(0);
            return u;
        });

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client, mockCache);
        final AuthUser authUser = underTest.getUser(request, doAfter, false);
        assertNotNull(authUser);
        verify(mockCache, times(1)).doAndCache(eq("johnshopkins.edu:hopkinsid:"+hopkinsId), any());
        verify(mockCache, times(0)).getOrDo(any(), any());
    }

}

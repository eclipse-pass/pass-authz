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
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EPPN_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.SCOPED_AFFILIATION_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.UNSCOPED_AFFILIATION_HEADER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.dataconservancy.pass.client.PassClient;

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

    @Before
    public void allowShibHeaders() {
        System.setProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS, "true");
    }

    @Test
    public void getFacultyUserTest() {

        final String displayName = "Bessie Cow";
        final String emailAddress = "bessie@farm.com";
        final String eppn = "bcow666@jhu.edu";
        final String affiliation = "STAFF;BREEDER;LACTATOR;FACULTY;DEAN";
        final String employeeId = "12345678";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);

        final AuthUser user = underTest.getUser(request);

        Assert.assertEquals(displayName, user.getName());
        Assert.assertEquals("bcow666", user.getInstitutionalId());
        Assert.assertEquals(emailAddress, user.getEmail());
        Assert.assertTrue(user.isFaculty());
        Assert.assertEquals(employeeId, user.getEmployeeId());
    }

    @Test
    public void getNonFacultyUserTest() {

        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String affiliation = "STAFF;WIDOWMAKER";
        final String employeeId = "87654321";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        Assert.assertEquals(displayName, user.getName());
        Assert.assertEquals("cbull999", user.getInstitutionalId());
        Assert.assertEquals(emailAddress, user.getEmail());
        Assert.assertFalse(user.isFaculty());
        Assert.assertEquals(employeeId, user.getEmployeeId());
    }

    @Test
    public void userPrincipalTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String affiliation = "STAFF;WIDOWMAKER";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        Assert.assertEquals(eppn, user.getPrincipal());
    }

    @Test
    public void domainTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String affiliation = "STAFF;WIDOWMAKER";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

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
        assertNull(user.getEmployeeId());
        assertNull(user.getId());
        assertNull(user.getInstitutionalId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
    }

    @Test
    public void attributeTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String affiliation = "STAFF;WIDOWMAKER";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getAttribute(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getAttribute(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getAttribute(EPPN_HEADER)).thenReturn(eppn);
        when(request.getAttribute(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getAttribute(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

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
    public void noShibHeadersByDefailtTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String affiliation = "STAFF;WIDOWMAKER";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        System.clearProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS);

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        assertNull(user.getEmployeeId());
        assertNull(user.getId());
        assertNull(user.getInstitutionalId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
    }

    @Test
    public void noShibHeadersIfExplicitlyFalseTest() {
        final String displayName = "Charlie Bull";
        final String emailAddress = "bull@rodeo.org";
        final String eppn = "cbull999@jhu.edu";
        final String affiliation = "STAFF;WIDOWMAKER";
        final String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        System.setProperty(ShibAuthUserProvider.CONFIG_SHIB_USE_HEADERS, "false");

        final ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        final AuthUser user = underTest.getUser(request);
        assertEquals(0, user.getDomains().size());
        assertNull(user.getEmail());
        assertNull(user.getEmployeeId());
        assertNull(user.getId());
        assertNull(user.getInstitutionalId());
        assertNull(user.getName());
        assertNull(user.getPrincipal());
    }

}

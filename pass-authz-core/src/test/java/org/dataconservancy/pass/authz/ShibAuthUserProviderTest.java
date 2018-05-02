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

import org.dataconservancy.pass.client.PassClient;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;

import static java.util.Arrays.asList;

import static org.dataconservancy.pass.authz.ShibAuthUserProvider.DISPLAY_NAME_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EMAIL_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.EPPN_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.SCOPED_AFFILIATION_HEADER;
import static org.dataconservancy.pass.authz.ShibAuthUserProvider.UNSCOPED_AFFILIATION_HEADER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

/**
 *
 * @author jrm@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class ShibAuthUserProviderTest {

    @Mock
    private HttpServletRequest request;
    
    @Mock
    private PassClient client;

    @Test
    public void getFacultyUserTest() {

        String displayName = "Bessie Cow";
        String emailAddress = "bessie@farm.com";
        String eppn = "bcow666@jhu.edu";
        String affiliation = "STAFF;BREEDER;LACTATOR;FACULTY;DEAN";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);

        ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        
        
        AuthUser user = underTest.getUser(request);

        Assert.assertEquals(displayName, user.getName());
        Assert.assertEquals("bcow666", user.getInstitutionalId());
        Assert.assertEquals(emailAddress, user.getEmail());
        Assert.assertTrue(user.isFaculty());
    }

    @Test
    public void getNonFacultyUserTest(){

        String displayName = "Charlie Bull";
        String emailAddress = "bull@rodeo.org";
        String eppn = "cbull999@jhu.edu";
        String affiliation = "STAFF;WIDOWMAKER";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);

        ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        AuthUser user = underTest.getUser(request);
        Assert.assertEquals(displayName, user.getName());
        Assert.assertEquals("cbull999", user.getInstitutionalId());
        Assert.assertEquals(emailAddress, user.getEmail());
        Assert.assertFalse(user.isFaculty());
    }
    
    @Test
    public void userPrincipalTest() {
        String displayName = "Charlie Bull";
        String emailAddress = "bull@rodeo.org";
        String eppn = "cbull999@jhu.edu";
        String affiliation = "STAFF;WIDOWMAKER";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);

        ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        AuthUser user = underTest.getUser(request);
        Assert.assertEquals(eppn, user.getPrincipal());
    }
    
    @Test
    public void domainTest() {
        String displayName = "Charlie Bull";
        String emailAddress = "bull@rodeo.org";
        String eppn = "cbull999@jhu.edu";
        String affiliation = "STAFF;WIDOWMAKER";
        String scopedAffiliation = "STAFF@jhu.edu;WIDOWMAKER@library.jhu.edu";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(SCOPED_AFFILIATION_HEADER)).thenReturn(scopedAffiliation);

        ShibAuthUserProvider underTest = new ShibAuthUserProvider(client);
        AuthUser user = underTest.getUser(request);
        assertEquals(2, user.getDomains().size());
        assertTrue(user.getDomains().containsAll(asList("jhu.edu", "library.jhu.edu")));
    }

}

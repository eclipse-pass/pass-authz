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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;

import static org.dataconservancy.pass.authz.ShibAuthUserProvider.*;
import static org.mockito.Mockito.when;

/**
 *
 * @author jrm@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class ShibAuthUserProviderTest {

    @Mock
    private HttpServletRequest request;

    @Test
    public void getFacultyUserTest() {

        String displayName = "Bessie Cow";
        String emailAddress = "bessie@farm.com";
        String eppn = "bcow666@jhu.edu";
        String affiliation = "STAFF;BREEDER;LACTATOR;FACULTY;DEAN";
        String employeeId = "12345678";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);

        ShibAuthUserProvider underTest = new ShibAuthUserProvider();
        AuthUser user = underTest.getUser(request);

        Assert.assertEquals(displayName, user.getName());
        Assert.assertEquals("bcow666", user.getInstitutionalId());
        Assert.assertEquals(emailAddress, user.getEmail());
        Assert.assertTrue(user.isFaculty());
        Assert.assertEquals(employeeId, user.getEmployeeId());
    }

    @Test
    public void getNonFacultyUserTest(){

        String displayName = "Charlie Bull";
        String emailAddress = "bull@rodeo.org";
        String eppn = "cbull999@jhu.edu";
        String affiliation = "STAFF;WIDOWMAKER";
        String employeeId = "87654321";

        when(request.getHeader(DISPLAY_NAME_HEADER)).thenReturn(displayName);
        when(request.getHeader(EMAIL_HEADER)).thenReturn(emailAddress);
        when(request.getHeader(EPPN_HEADER)).thenReturn(eppn);
        when(request.getHeader(UNSCOPED_AFFILIATION_HEADER)).thenReturn(affiliation);
        when(request.getHeader(EMPLOYEE_ID)).thenReturn(employeeId);

        ShibAuthUserProvider underTest = new ShibAuthUserProvider();
        AuthUser user = underTest.getUser(request);
        Assert.assertEquals(displayName, user.getName());
        Assert.assertEquals("cbull999", user.getInstitutionalId());
        Assert.assertEquals(emailAddress, user.getEmail());
        Assert.assertFalse(user.isFaculty());
        Assert.assertEquals(employeeId, user.getEmployeeId());
    }

}

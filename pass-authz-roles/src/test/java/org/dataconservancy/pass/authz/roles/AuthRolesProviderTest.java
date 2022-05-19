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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.dataconservancy.pass.authz.roles.AuthRolesProvider.getRoles;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.dataconservancy.pass.authz.AuthUser;
import org.dataconservancy.pass.model.User;
import org.dataconservancy.pass.model.User.Role;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author apb@jhu.edu
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthRolesProviderTest {

    AuthUser authUser;

    User user;

    final String domain = "ruminant.edu";

    @Before
    public void setUp() {
        user = new User();
        user.setId(URI.create("test:" + UUID.randomUUID().toString()));
        authUser = new AuthUser();
        authUser.setPrincipal("gladys@ruminant.edu");
        authUser.getDomains().add("ruminant.edu");
        authUser.setId(user.getId());
        authUser.setUser(user);

    }

    // Verify that an empty AuthUser simply results in no domains
    @Test
    public void emptyUserTest() {
        final AuthUser empty = new AuthUser();
        assertTrue(getRoles(empty).isEmpty());
    }

    // Somebody who doesn't have a User in PASS shouldn't have any roles.
    @Test
    public void noUserInPassTest() {
        authUser.setUser(null);

        assertTrue(getRoles(authUser).isEmpty());
    }

    // Somebody that hasn't been assigned any PASS roles should have only their userID as a role.
    @Test
    public void noPassRolesTest() {
        user.setRoles(emptyList());

        final Set<URI> roles = getRoles(authUser);
        assertEquals(1, roles.size());
        assertTrue(roles.contains(user.getId()));
    }

    @Test
    public void singleRoleTest() {
        user.setRoles(asList(Role.SUBMITTER));

        final Set<URI> roles = getRoles(authUser);
        assertEquals(2, roles.size());
    }

    @Test
    public void twoRolesTest() {
        user.setRoles(asList(Role.SUBMITTER, Role.ADMIN));

        final Set<URI> roles = getRoles(authUser);
        assertEquals(3, roles.size());
    }

    // Make sure all submitters from the same institution share the same submitter role.
    @Test
    public void twoSubmittersSameRoleTest() {
        final User user2 = new User();
        user2.setId(URI.create("test:" + UUID.randomUUID().toString()));
        final AuthUser authUser2 = new AuthUser();
        authUser2.setPrincipal("clarabelle@ruminant.edu");
        authUser2.getDomains().addAll(authUser.getDomains());
        authUser2.setUser(user2);

        user.setRoles(asList(Role.SUBMITTER));
        user2.setRoles(asList(Role.SUBMITTER));

        final Set<URI> roles1 = getRoles(authUser);
        final Set<URI> roles2 = getRoles(authUser2);

        System.out.println(roles1);
        System.out.println(roles2);

        final Set<URI> commonRoles = new HashSet<>(roles1);
        commonRoles.retainAll(roles2);

        assertEquals(1, commonRoles.size());
        assertEquals(2, roles1.size());
        assertEquals(2, roles2.size());
    }

    // Make sure that submitters at different institutions have different submitter roles
    @Test
    public void twoSubmittersDifferentInstitutionsTest() {
        final User user2 = new User();
        user2.setId(URI.create("test:" + UUID.randomUUID().toString()));
        final AuthUser authUser2 = new AuthUser();
        authUser2.setPrincipal("clarabelle@ungulate.edu");
        authUser2.getDomains().add("ungulate.edu");
        authUser2.setUser(user2);

        user.setRoles(asList(Role.SUBMITTER));
        user2.setRoles(asList(Role.SUBMITTER));

        final Set<URI> roles1 = getRoles(authUser);
        final Set<URI> roles2 = getRoles(authUser2);

        final Set<URI> commonRoles = new HashSet<>(roles1);
        commonRoles.retainAll(roles2);

        assertEquals(0, commonRoles.size());
        assertEquals(2, roles1.size());
        assertEquals(2, roles2.size());
    }

}

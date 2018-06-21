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

package org.dataconservancy.pass.authz.acl;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.model.Grant;
import org.dataconservancy.pass.model.Submission;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class PolicyEngine {

    private final PassClient client;

    private final ACLManager acls;

    private final URI backend;

    Logger LOG = LoggerFactory.getLogger(PolicyEngine.class);

    public PolicyEngine(PassClient client, ACLManager manager, URI backend) {
        this.client = client;
        this.acls = manager;
        this.backend = backend;
    }

    // PIs and Co-PIs can append to grants, as can the backend
    public void updateGrant(URI uri) {
        final Grant grant = client.readResource(uri, Grant.class);

        final Set<URI> authUsers = new HashSet<>();
        if (grant.getPi() != null) {
            authUsers.add(grant.getPi());
        }
        authUsers.addAll(grant.getCoPis());
        if (backend != null) {
            authUsers.add(backend);
        }

        LOG.info("Updating permissions of grant {}", uri);
        LOG.debug("Granting write on grant {} to {}", uri, authUsers);
        acls.setPermissions(uri)
                .grantRead(authUsers)
                .grantWrite(authUsers)
                .perform();
    }

    // Grant write on submissions to the user and backend
    public void updateSubmission(URI uri) {
        final Submission submission = client.readResource(uri, Submission.class);

        final Set<URI> authUsers = new HashSet<>();
        if (submission.getUser() != null) {
            authUsers.add(submission.getUser());
        }

        if (backend != null) {
            authUsers.add(backend);
        }

        LOG.info("Updating permissions of submission {}", uri);
        LOG.debug("Granting write on submission {} to {}", uri, authUsers);
        acls.setPermissions(uri)
                .grantRead(authUsers)
                .grantWrite(authUsers)
                .perform();
    }
}

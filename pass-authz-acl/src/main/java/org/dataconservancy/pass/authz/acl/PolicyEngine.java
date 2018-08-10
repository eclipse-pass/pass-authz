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
import org.dataconservancy.pass.model.Submission;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class PolicyEngine {

    private final PassClient client;

    private final ACLManager acls;

    private URI backendRole;

    private URI submitterRole;

    private URI grantAdminRole;

    Logger LOG = LoggerFactory.getLogger(PolicyEngine.class);

    public PolicyEngine(PassClient client, ACLManager manager) {
        this.client = client;
        this.acls = manager;
    }

    public void setSubmitterRole(URI submitterRole) {
        LOG.info("Using submitter role: " + submitterRole);
        this.submitterRole = submitterRole;
    }

    public void setBackendRole(URI backendRole) {
        LOG.info("Using backend role: " + backendRole);
        this.backendRole = backendRole;
    }

    public void setAdminRole(URI adminRole) {
        LOG.info("Using grant admin role " + adminRole);
        this.grantAdminRole = adminRole;
    }

    // Grant write on submissions to the user and backend
    public void updateSubmission(URI uri) {
        final Submission submission = client.readResource(uri, Submission.class);

        final Set<URI> authReaders = new HashSet<>();
        final Set<URI> authWriters = new HashSet<>();

        if (submission.getUser() != null) {
            authReaders.add(submission.getUser());

            // If a submission is "submitted=true", then it's frozen.
            if (submission.getSubmitted() == null || !submission.getSubmitted()) {
                // Not frozen, allow writes
                authWriters.add(submission.getUser());
            }
        }

        if (backendRole != null) {
            authReaders.add(backendRole);
            authWriters.add(backendRole);
        }

        if (grantAdminRole != null) {
            authReaders.add(grantAdminRole);
        }

        if (submitterRole != null) {
            authReaders.add(submitterRole);
        }

        LOG.debug("Granding read of submission {} to {}", authReaders);
        LOG.debug("Granting write on submission {} to {}", uri, authWriters);
        acls.setPermissions(uri)
                .grantRead(authReaders)
                .grantWrite(authWriters)
                .perform();
    }
}

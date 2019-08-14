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

package org.dataconservancy.pass.authz.tools.main;

import java.net.URI;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.authz.acl.PolicyEngine;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.client.util.ConfigUtil;
import org.dataconservancy.pass.model.Submission;
import org.dataconservancy.pass.model.SubmissionEvent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Optional.ofNullable;

/**
 * @author apb@jhu.edu
 */
public class PermissionsUpdater {

    static final URI ROLE_BASE = ofNullable(System.getProperties().getProperty(Const.ROLE_BASE,
            System.getenv(Const.ROLE_BASE.toUpperCase().replace(".", "_"))))
            .map(uri -> uri.endsWith("#") ? uri : uri + "#")
            .map(URI::create)
            .orElse(URI.create("http://oapass.org/ns/roles/johnshopkins.edu#"));

    static final URI PASS_BACKEND_ROLE = URI.create(ROLE_BASE.toString() + "pass-backend");

    static final URI PASS_GRANTADMIN_ROLE = URI.create(ROLE_BASE.toString() + "admin");

    static final URI PASS_SUBMITTER_ROLE = URI.create(ROLE_BASE.toString() + "submitter");

    static final Logger LOG = LoggerFactory.getLogger(PermissionsUpdater.class);

    static final ExecutorService exe = Executors.newCachedThreadPool();

    public static void main(String[] args) throws Exception {

        final ACLManager manager = new ACLManager();
        final PassClient client = PassClientFactory.getPassClient();

        final PolicyEngine authzPolicy = new PolicyEngine(client, manager);
        authzPolicy.setBackendRole(PASS_BACKEND_ROLE);
        authzPolicy.setAdminRole(PASS_GRANTADMIN_ROLE);
        authzPolicy.setSubmitterRole(PASS_SUBMITTER_ROLE);

        final String type = ConfigUtil.getSystemProperty("type", null);

        System.out.println("Specified type is: " + type);

        if (type == null || type.equals(Submission.class.getSimpleName())) {
            LOG.info("Visiting submissions...");
            final Future<Integer> submissions = exe.submit(() -> client.processAllEntities(
                    authzPolicy::updateSubmission,
                    Submission.class));

            LOG.info("Processed {} submissions", submissions.get());
        }

        if (type == null || type.equals(SubmissionEvent.class.getSimpleName())) {
            LOG.info("Visiting submissionEvents...");
            final Future<Integer> submissionEvents = exe.submit(() -> client.processAllEntities(
                    authzPolicy::updateSubmissionEvent,
                    SubmissionEvent.class));

            LOG.info("Processed {} submissionEvents", submissionEvents.get());
        }

        exe.shutdown();
    }
}

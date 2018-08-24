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

package org.dataconservancy.pass.authz.listener;

import java.util.List;

import javax.jms.ConnectionFactory;

import org.dataconservancy.pass.authz.acl.PolicyEngine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class AuthzListener {

    String SUBMISSION_TYPE = "http://oapass.org/ns/pass#Submission";

    private final ConnectionFactory factory;

    private final PolicyEngine aclPolicies;

    private final String queueName;

    Logger LOG = LoggerFactory.getLogger(AuthzListener.class);

    public AuthzListener(ConnectionFactory jmsFactory, PolicyEngine policyEngine, String queueName) {
        this.factory = jmsFactory;
        this.aclPolicies = policyEngine;
        this.queueName = queueName;
    }

    public void listen() {
        try (JMSClient client = new JMSClient(factory)) {
            LOG.info("Listening on queue {}", queueName);
            client.listen(queueName, msg -> {
                try {
                    final FedoraMessage fm = FedoraMessageConverter.convert(msg);

                    if (fm.getAction() == FedoraAction.CREATED || fm.getAction() == FedoraAction.MODIFIED) {
                        final List<String> types = fm.getResourceTypes();

                        if (types.contains(SUBMISSION_TYPE)) {
                            aclPolicies.updateSubmission(fm.getResourceURI());
                            LOG.debug("Handling Submission message for {} ", fm.getAction());
                        } else {
                            LOG.debug("Ignoring message with irrelevant types ", types);
                        }
                    } else {
                        LOG.debug("Ignoring irelevant action {}", fm.getAction());
                    }

                } catch (final Exception e) {
                    throw new RuntimeException("Error listening for messages", e);
                }
            });

            try {
                Thread.currentThread().join();
            } catch (final InterruptedException e) {
                LOG.info("Interrupted");
                Thread.currentThread().interrupt();
            }
        }
    }

}

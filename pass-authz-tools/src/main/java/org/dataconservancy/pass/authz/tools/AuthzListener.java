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

package org.dataconservancy.pass.authz.tools;

import java.util.List;

import javax.jms.ConnectionFactory;

import org.dataconservancy.pass.authz.acl.PolicyEngine;

/**
 * @author apb@jhu.edu
 */
public class AuthzListener {

    String SUBMISSION_TYPE = "http://oapass.org/ns/pass#Submission";

    String GRANT_TYPE = "http://oapass.org/ns/pass#Grant";

    private final ConnectionFactory factory;

    private final PolicyEngine aclPolicies;

    public AuthzListener(ConnectionFactory jmsFactory, PolicyEngine policyEngine) {
        this.factory = jmsFactory;
        this.aclPolicies = policyEngine;
    }

    public void listen() {
        try (JMSClient client = new JMSClient(factory)) {
            client.listen("authz", msg -> {
                try {
                    final FedoraMessage fm = FedoraMessageConverter.convert(msg);

                    if (fm.getAction() == FedoraAction.CREATED || fm.getAction() == FedoraAction.MODIFIED) {
                        final List<String> types = fm.getResourceTypes();

                        if (types.contains(SUBMISSION_TYPE)) {
                            aclPolicies.updateSubmission(fm.getResourceURI());
                        } else if (types.contains(GRANT_TYPE)) {
                            aclPolicies.updateGrant(fm.getResourceURI());
                        }
                    }

                } catch (final Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

}

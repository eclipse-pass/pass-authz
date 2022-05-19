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

import static java.util.Optional.ofNullable;
import static org.dataconservancy.pass.authz.ConfigUtil.getValue;
import static org.dataconservancy.pass.authz.LogUtil.adjustLogLevels;

import java.net.URI;
import javax.jms.ConnectionFactory;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.authz.acl.PolicyEngine;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class AuthzListenerService {

    private AuthzListenerService() {
    }

    static final Logger LOG = LoggerFactory.getLogger(AuthzListenerService.class);

    public static void main(String[] args) {
        adjustLogLevels();

        final PassClient client = PassClientFactory.getPassClient();
        final ACLManager manager = new ACLManager();
        final String queue = getValue("pass.authz.queue");

        final PolicyEngine policies = new PolicyEngine(client, manager);
        policies.setBackendRole(ofNullable(getValue("pass.backend.role")).map(URI::create).orElse(null));
        policies.setAdminRole(ofNullable(getValue("pass.grantadmin.role")).map(URI::create).orElse(null));
        policies.setSubmitterRole(ofNullable(getValue("pass.submitter.role")).map(URI::create).orElse(null));

        final AuthzListener listener = new AuthzListener(buildConnectionFactory(), policies, queue);

        LOG.info("Starting listener...");
        listener.listen();
    }

    private static ConnectionFactory buildConnectionFactory() {
        final ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory();
        factory.setBrokerURL(ofNullable(getValue("jms.brokerUrl")).orElse("tcp://localhost:61616"));
        factory.setUserName(getValue("jms.username"));
        factory.setPassword(getValue("jms.password"));

        return factory;
    }

}

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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageListener;
import javax.jms.MessageProducer;
import javax.jms.Session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class JMSClient implements AutoCloseable {

    private Connection conn;

    private volatile boolean connected = false;

    private static final Logger LOG = LoggerFactory.getLogger(JMSClient.class);

    private ConnectionFactory connectionFactory;

    private final List<Consumer<Session>> sessionListeners = Collections.synchronizedList(new ArrayList<>());

    private MessageProducer producer;

    private Session session;

    public void setConnectionFactory(ConnectionFactory factory) {
        this.connectionFactory = factory;
    }

    public JMSClient(ConnectionFactory factory) {
        this.connectionFactory = factory;
        init();
    }

    public JMSClient() {

    }

    public void init() {

        if (this.producer == null) {
            addSessionListener(s -> {
                try {
                    this.producer = session.createProducer(null);
                } catch (final JMSException e) {
                    throw new JmsRuntimeException(e);
                }
            });
        }

        connect();
    }

    private void addSessionListener(Consumer<Session> listener) {
        this.sessionListeners.add(listener);
        if (connected) {
            listener.accept(session);
        }
    }

    public void listen(String queue, MessageListener listener) {
        this.addSessionListener(s -> {
            try {
                final Destination dest = s.createQueue(queue);
                s.createConsumer(dest).setMessageListener(listener);
                LOG.info("Listening on " + dest);
            } catch (final JMSException e) {
                throw new JmsRuntimeException(e);
            }
        });
    }

    public Supplier<Session> getSessionSupplier() {
        return () -> {
            while (!connected) {
                try {
                    Thread.sleep(1000);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Interrupted", e);
                }
            }

            return session;
        };
    }

    public synchronized void write(String queue, Message message) {
        LOG.debug("Sending message to queue {}", queue);
        while (!connected) {
            try {
                Thread.sleep(1000);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted", e);
            }
        }

        try {
            producer.send(session.createQueue(queue), message);
        } catch (final JMSException e) {
            throw new RuntimeException("Error writing to queue " + queue, e);
        }
    }

    private void connect() {
        while (!connected) {
            try {
                conn = connectionFactory.createConnection();
                conn.start();

                session = conn.createSession(false, Session.AUTO_ACKNOWLEDGE);

                sessionListeners.forEach(s -> s.accept(session));

                conn.setExceptionListener(e -> {
                    if (connected) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Connection disrupted", e);
                        } else {
                            LOG.info("Connection disrupted", e.getMessage());
                        }
                        close();
                        connect();
                    }

                });
                connected = true;
            } catch (final JMSException e) {
                try {
                    if (conn != null) {
                        conn.close();
                    }
                } catch (final JMSException j) {
                    LOG.warn("Error closing connection, j");
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("JMS error, re-trying", e);
                } else {
                    LOG.info("JMS error: {}, re-connecting", e.getMessage());
                }
                try {
                    Thread.sleep(2000);
                } catch (final InterruptedException i) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    @Override
    public void close() {
        try {
            LOG.info("Closing ActiveMQ Sessions");
            connected = false;
            producer.close();
            session.close();
            conn.close();
        } catch (final JMSException j) {
            LOG.debug("Exception while closing connection", j);
        }
    }

    @SuppressWarnings("serial")
    private class JmsRuntimeException extends RuntimeException {

        public JmsRuntimeException(Throwable e) {
            super(e.getMessage(), e);
        }
    }
}

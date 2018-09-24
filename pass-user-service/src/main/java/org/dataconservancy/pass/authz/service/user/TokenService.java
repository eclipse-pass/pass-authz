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

package org.dataconservancy.pass.authz.service.user;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Optional.ofNullable;
import static org.dataconservancy.pass.authz.usertoken.Key.USER_TOKEN_KEY_PROPERTY;
import static org.dataconservancy.pass.client.util.ConfigUtil.getSystemProperty;

import java.net.URI;

import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.authz.usertoken.BadTokenException;
import org.dataconservancy.pass.authz.usertoken.Token;
import org.dataconservancy.pass.authz.usertoken.TokenFactory;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.model.Submission;
import org.dataconservancy.pass.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
class TokenService {

    TokenFactory tokenFactory;

    PassClient client;

    ACLManager acls = new ACLManager();

    static final Logger LOG = LoggerFactory.getLogger(TokenService.class);

    public TokenService() {
        tokenFactory = ofNullable(getSystemProperty(USER_TOKEN_KEY_PROPERTY, null)).map(TokenFactory::new).orElse(
                null);
        client = PassClientFactory.getPassClient();
    }

    public TokenService(TokenFactory factory, PassClient client) {
        this.tokenFactory = factory;
        this.client = client;
    }

    Token fromQueryString(String token) {

        if (token == null) {
            LOG.debug("No query string, therefore no user token");
            return null;
        } else if (tokenFactory == null) {
            throw new BadTokenException("Server is not set up to process user tokens, please do not provide one");
        }

        final URI uri = URI.create("?" + token);

        if (tokenFactory.hasToken(uri)) {
            LOG.info("Got token from query string");
            return tokenFactory.fromUri(uri);
        }

        LOG.debug("No user token provided");
        return null;
    }

    public boolean replacePlaceholder(User user, Token token) {

        if (user == null || user.getId() == null) {
            throw new NullPointerException("Cannot process token for a null or unidentified user");
        }

        final Submission submission;
        try {
            submission = client.readResource(token.getPassResource(), Submission.class);

            if (submission == null) {
                throw new RuntimeException(String.format("Submission <%s> not found", token.getPassResource()));
            }
        } catch (final Exception e) {
            LOG.warn(format("Failed reading submission <%s>, cannot further process user token given by user <%s>",
                    token.getPassResource(), user.getId()), e);
            throw new BadTokenException(format("The submission <%s> is no longer accessible", token
                    .getPassResource()), e);
        }

        if (token.getReference().equals(submission.getSubmitter())) {
            LOG.info("User <{}> will be made a submitter for <{}>, replacing placeholder <{}>",
                    user.getId(),
                    submission.getId(),
                    submission.getSubmitter());

            submission.setSubmitter(user.getId());
            client.updateResource(submission);
            return true;

        } else if (user.getId().equals(submission.getSubmitter())) {
            LOG.info("User <{}> already in place as the submitter.  Ignoring user token");
            return false;
        } else {
            final String message = format(
                    "New user token does not match expected placeholer <%s> on submission <%s>; found <%s> instead",
                    token.getReference(), submission.getId(), submission.getSubmitter());

            LOG.warn(message);
            throw new BadTokenException(message);
        }
    }

    public void addWritePermissions(User user, Token token) {
        acls.addPermissions(token.getPassResource()).grantWrite(asList(user.getId())).perform();
    }
}

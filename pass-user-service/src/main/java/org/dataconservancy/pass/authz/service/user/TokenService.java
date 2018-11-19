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

package org.dataconservancy.pass.authz.service.user;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Optional.ofNullable;
import static org.dataconservancy.pass.authz.usertoken.Key.USER_TOKEN_KEY_PROPERTY;
import static org.dataconservancy.pass.client.util.ConfigUtil.getSystemProperty;

import java.net.URI;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.dataconservancy.pass.authz.acl.ACLManager;
import org.dataconservancy.pass.authz.usertoken.BadTokenException;
import org.dataconservancy.pass.authz.usertoken.Token;
import org.dataconservancy.pass.authz.usertoken.TokenFactory;
import org.dataconservancy.pass.client.PassClient;
import org.dataconservancy.pass.client.PassClientFactory;
import org.dataconservancy.pass.model.Submission;
import org.dataconservancy.pass.model.User;
import org.dataconservancy.pass.support.messaging.cri.CriticalPath;
import org.dataconservancy.pass.support.messaging.cri.CriticalRepositoryInteraction;
import org.dataconservancy.pass.support.messaging.cri.CriticalRepositoryInteraction.CriticalResult;
import org.dataconservancy.pass.support.messaging.cri.DefaultConflictHandler;
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

    CriticalRepositoryInteraction cri;

    public TokenService() {
        tokenFactory = ofNullable(getSystemProperty(USER_TOKEN_KEY_PROPERTY, null)).map(TokenFactory::new).orElse(
                null);
        client = PassClientFactory.getPassClient();
        cri = new CriticalPath(client, new DefaultConflictHandler(client));
    }

    public TokenService(TokenFactory factory, PassClient client) {
        this.tokenFactory = factory;
        this.client = client;
        cri = new CriticalPath(client, new DefaultConflictHandler(client));
    }

    public TokenService(TokenFactory tokenFactory, PassClient client, CriticalRepositoryInteraction cri) {
        this.tokenFactory = tokenFactory;
        this.client = client;
        this.cri = cri;
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

    /**
     * Updates the submission by validating the user token and injecting the new user.
     *
     * @param user The new user
     * @param token User token
     * @return true, if the submission is updated.
     */
    public boolean enactUserToken(User user, Token token) {

        if (user == null || user.getId() == null) {
            throw new NullPointerException("Cannot process token for a null or unidentified user");
        }

        final CriticalResult<Submission, Submission> cr = cri.performCritical(token.getPassResource(), Submission.class,
                preconditions(user, token),
                postConditions(user),
                criticalSection(user));

        if (!cr.success()) {
            if (!cr.resource().isPresent()) {
                LOG.warn("Submission <{}> not found", token.getPassResource());
                LOG.warn(format("Failed reading submission <%s>, cannot further process user token given by user <%s>",
                        token.getPassResource(), user.getId()));
                throw new BadTokenException(format("The submission <%s> is no longer accessible", token
                        .getPassResource()));
            }

            throwIfPresent(cr, null);
            return false;
        }

        return true;
    }

    public void addWritePermissions(User user, Token token) {
        acls.addPermissions(token.getPassResource()).grantWrite(asList(user.getId())).perform();
    }

    /**
     * Answers a {@code Function} that associates the {@code User} with the {@code Submission} as
     * {@code Submission.submitter}, and nulls out {@code Submission.submitterEmail} and
     * {@code Submission.submitterName}.
     *
     * @param user the {@code User} presenting the token
     * @return a {@code Function} associating the supplied {@code User} with the {@code Submission}
     */
    static Function<Submission, Submission> criticalSection(User user) {
        return (criSubmission) -> {
            criSubmission.setSubmitterEmail(null);
            criSubmission.setSubmitterName(null);
            criSubmission.setSubmitter(user.getId());
            return criSubmission;
        };
    }

    /**
     * Answers a {@code Predicate&lt;Submission&gt;} that insures:
     * <ul>
     *     <li>{@code Submission.submitterEmail} is {@code null}</li>
     *     <li>{@code Submission.submitterName} is {@code null}</li>
     *     <li>{@code Submission.submitter} references the supplied {@code User}</li>
     * </ul>
     *
     * If all postconditions are met, the {@code Predicate} returns {@code true}, otherwise {@code false}.
     *
     *
     * @param user the {@code User} associated with the {@code Submission}
     * @return the {@code Predicate} providing post-conditions insuring the {@code User} was properly applied to the
     *         {@code Submission}
     */
    static Predicate<Submission> postConditions(User user) {
        return (criSubmission) -> {
            if (criSubmission.getSubmitterEmail() == null &&
                    criSubmission.getSubmitterName() == null &&
                    criSubmission.getSubmitter().equals(user.getId())) {

                LOG.info("User <{}> made a submitter for <{}>, based on matching e-mail <{}>",
                        user.getId(),
                        criSubmission.getId(),
                        criSubmission.getSubmitterEmail());
                return true;
            }

            return false;
        };
    }

    /**
     * Answers a {@code Predicate&lt;Submission&gt;} that insures:
     * <ul>
     *     <li>The token reference equals the {@code Submission.submitterEmail}</li>
     *     <li>An existing {@code Submission.submitter} is the same {@code User} referenced by the token</li>
     * </ul>
     *
     * If all preconditions are met, the {@code Predicate} returns {@code true}.
     *
     * If the {@code User} is already associated with the {@code Submission} as the {@code Submission.submitter},
     * the {@code Predicate} returns {@code false}, because applying the critical section (associating the {@code User}
     * to the {@code Submission}) would be redundant.
     *
     * If any preconditions fail, the {@code Predicate} returns {@code false}.
     *
     * @param user the {@code User} presenting the token to be associated with the {@code Submission}
     * @param token the token
     * @return the {@code Predicate} providing pre-conditions for associating the {@code User} with a {@code Submission}
     */
    static Predicate<Submission> preconditions(User user, Token token) {
        return (s) -> {
            if (token.getReference().equals(s.getSubmitterEmail())) {
                if (s.getSubmitter() != null && !s.getSubmitter().equals(token.getReference()) &&
                        !s.getSubmitter().equals(user.getId())) {
                    throw new BadTokenException(format(
                            "There is already a submitter <%s> for the criSubmission <%s>, and it isn't the intended " +
                                    "user <%s>  Refusing to apply the token for <%s>",
                            s.getSubmitter(), s.getId(), user.getId(), token.getReference()));
                }

                return true;
            } else if (user.getId().equals(s.getSubmitter())) {
                LOG.info("User <{}> already in place as the submitter.  Ignoring user token", user.getId());
                return false;
            } else {
                final String message = format(
                        "New user token does not match expected e-mail <%s> on criSubmission <%s>; found <%s> instead",
                        token.getReference(), s.getId(), s.getSubmitterEmail());

                LOG.warn(message);
                throw new BadTokenException(message);
            }
        };
    }

    /**
     * Throw the exception present in the {@code CriticalResult} as a {@code RuntimeException}.  Wraps the underlying
     * {@code Throwable} if necessary.  If a {@code Throwable} isn't present, throw the {@code RuntimeException}
     * supplied by the non-null {@code Supplier&lt;RuntimeException&gt;}
     *
     * @param cr a {@code CriticalResult} that may contain a {@code Throwable}
     * @param orElse a {@code Supplier} of {@code RuntimeException} that may be thrown if the {@code CriticalResult}
     *               {@code Throwable} isn't present.  May be {@code null}.
     */
    private static void throwIfPresent(CriticalResult<Submission, Submission> cr, Supplier<RuntimeException> orElse) {
        if (cr.throwable().isPresent()) {
            if (cr.throwable().get() instanceof RuntimeException) {
                throw (RuntimeException) cr.throwable().get();
            } else {
                throw new RuntimeException(cr.throwable().get());
            }
        } else if (orElse != null) {
            throw orElse.get();
        }
    }
}

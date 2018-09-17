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

package org.dataconservancy.pass.authz.usertoken;

import static org.dataconservancy.pass.authz.usertoken.Token.USER_TOKEN_PARAM;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Factory for creating tokens, or extracting them from URIs.
 *
 * @author apb@jhu.edu
 */
public class TokenFactory {

    final Codec codec;

    static final Pattern userTokenPattern = Pattern.compile(".*" + USER_TOKEN_PARAM + "=([A-Z2-7]+).*");

    /**
     * Instantiate a TokenFactory that will (de)serialize tokens using the given encryption key
     *
     * @param key Key to use for serialization and deserialization of the token,
     */
    public TokenFactory(Key key) {
        this.codec = new Codec(key);
    }

    /**
     * Instantiate the TokenFactory with a base32-encoded key.
     * <p>
     * This is typically how a TokenFactory is instantiated from configuration, using an
     * easily-serializable-as-a-string key.
     * </p>
     *
     * @param key Base32 encoded encryption key.
     */
    public TokenFactory(String key) {
        this.codec = new Codec(Key.fromString(key));
    }

    /**
     * Start building a {@link Token} from a PASS resource URI.
     *
     * @param resourceUri URI to a PASS resource. Will be encoded in the token when finished. Nust not be null.
     * @return in-progress token builder. The next step is to tomplete the token by providing a URI reference via
     *         {@link Builder#withReference(URI)}.
     */
    public Builder forPassResource(URI resourceUri) {
        return new Builder(resourceUri);
    }

    /**
     * Decode a token from an encoded string.
     * <p>
     * Included for completeness, just in case a token outside of the context of a URL needs decoding. Prefer
     * {@link #fromUri(URI)}
     * </p>
     *
     * @param encoded String containing the encoded token.
     * @return The token.
     */
    public Token from(String encoded) {
        return new Token(codec, encoded);
    }

    /**
     * Decode a token from a URI containing a userToken parameter.
     *
     * @param uri The URI to inspect
     * @return the Token, or null if none are present.
     */
    public Token fromUri(URI uri) {
        final Matcher tokenMatcher = userTokenPattern.matcher(uri.getQuery());
        if (tokenMatcher.matches()) {
            return new Token(codec, tokenMatcher.group(1));
        } else {
            return null;
        }
    }

    /**
     * Determine if a URI has a token in it.
     *
     * @param uri URI to inspect.
     * @return true, if the URI has a token parameter in it.
     */
    public boolean hasToken(URI uri) {
        return userTokenPattern.matcher(uri.getQuery()).matches();
    }

    /**
     * builder for an in-progress/incomplete token.
     *
     * @author apb@jhu.edu
     */
    public class Builder {

        private final URI resource;

        private Builder(URI resource) {
            this.resource = resource;
        }

        /**
         * Finish building a token, given a URI reference.
         * <p>
         * Token building started with {@link TokenFactory#forPassResource(URI)}, and finishes here.
         * </p>
         *
         * @param reference URI/reference associated with this token (e.g. in the proxy use case, the mailto URI).
         * @return finished Token.
         */
        public Token withReference(URI reference) {
            return new Token(codec, resource, reference);
        }
    }
}

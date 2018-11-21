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

import static java.net.URLDecoder.decode;
import static java.net.URLEncoder.encode;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

/**
 * User token; encodes the identity of a PASS resource, and a reference/link within it.
 *
 * @author apb@jhu.edu
 */
public class Token {

    static final int REFERENCE_URI_INDEX = 0;

    static final int RESOURCE_URI_INDEX = 1;

    public static final String USER_TOKEN_PARAM = "userToken";

    final URI resource;

    final URI reference;

    final Codec codec;

    // Internal constructor
    Token(Codec codec, URI resource, URI reference) {

        if (reference == null) {
            throw new NullPointerException("Reference URI must not be null");
        } else if (resource == null) {
            throw new NullPointerException("PASS resource URI must not be null");
        }

        this.resource = resource;

        this.reference = reference;

        this.codec = codec;
    }

    // Internal constructor
    Token(Codec codec, String encoded) {

        this.codec = codec;

        final String[] uris = codec.decrypt(encoded).split(",");

        if (uris.length != 2) {
            throw new RuntimeException("Malformed token:  token must encode two URIs");
        }

        try {
            resource = URI.create(decode(uris[RESOURCE_URI_INDEX], UTF_8.name()));
            reference = URI.create(decode(uris[REFERENCE_URI_INDEX], UTF_8.name()));

        } catch (final UnsupportedEncodingException e) {
            // Should never happen
            throw new RuntimeException("Gosh, your platform does not support UTF-8??");
        }
    }

    /**
     * Get the identity of the PASS resource encoded in this token.
     *
     * @return URI of the PASS resource, will not be null;
     */
    public URI getPassResource() {
        return resource;
    }

    /**
     * Get a URI/reference from this token.
     * <p>
     * In the PASS proxy use case, this is typically a placeholder URI representing a new "needs to be added to PASS"
     * user's e-mail.
     * </p>
     *
     * @return URI reference, will not be null.
     */
    public URI getReference() {
        return reference;
    }

    /**
     * Add the token as a parameter to the given URI.
     *
     * @param anyUri the URI for which to append this token as a parameter.
     * @return URI that is identical to the originally given URI, except for the addition of the token as a URI
     *         parameter.
     */
    public URI addTo(URI anyUri) {
        String qs = anyUri.getRawQuery();
        if (qs == null) {
            qs = String.format("%s=%s", USER_TOKEN_PARAM, toString());
        } else {
            qs += String.format("&%s=%s", USER_TOKEN_PARAM, toString());
        }

        try {
            return URI.create(new URI(anyUri.getScheme(), anyUri.getUserInfo(), anyUri.getHost(), anyUri.getPort(),
                    anyUri.getRawPath(), qs, anyUri.getRawFragment())
                            .toString().replace("%25", "%"));
        } catch (final URISyntaxException e) {
            throw new RuntimeException("Could not add token to URI " + anyUri, e);
        }
    }

    /**
     * Return token as an encrypted, base32 encoded string.
     */
    @Override
    public String toString() {
        try {
            final String[] uris = new String[2];
            uris[RESOURCE_URI_INDEX] = encode(resource.toString(), UTF_8.toString());
            uris[REFERENCE_URI_INDEX] = encode(reference.toString(), UTF_8.toString());

            return codec.encrypt(String.join(",", uris));
        } catch (final UnsupportedEncodingException e) {
            // Should never happen
            throw new RuntimeException("Gosh, your platform does not support UTF-8??");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Token that = (Token) o;
        return Objects.equals(resource, that.resource) &&
                Objects.equals(reference, that.reference);
    }

    @Override
    public int hashCode() {
        return Objects.hash(resource, reference);
    }
}

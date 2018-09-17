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

package org.dataconservancy.pass.authz.usertoken;

import static java.net.URLEncoder.encode;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.UUID;

import org.junit.Test;

/**
 * @author apb@jhu.edu
 */
public class TokenTest {

    @Test(expected = NullPointerException.class)
    public void nullReferenceTest() {
        new Token(new Codec(Key.generate()), randomUri(), null);
    }

    @Test(expected = NullPointerException.class)
    public void nullResourceTest() {
        new Token(new Codec(Key.generate()), null, randomUri());
    }

    @Test
    public void roundTripTest() {

        final URI resource = randomUri();

        final URI reference = randomUri();

        final Codec codec = new Codec(Key.generate());

        final Token created = new Token(codec, resource, reference);

        final Token fromString = new Token(codec, created.toString());

        assertEquals(resource, fromString.getPassResource());
        assertEquals(reference, fromString.getReference());
    }

    @Test(expected = RuntimeException.class)
    public void garbageTokenTest() {

        final Codec codec = new Codec(Key.generate());

        new Token(codec, "blah");
    }

    @Test(expected = RuntimeException.class)
    public void tooFewUrisTest() {
        final Codec codec = new Codec(Key.generate());

        String badTokenContent = null;
        try {
            badTokenContent = encode("http://example.org", UTF_8.toString());
        } catch (final UnsupportedEncodingException e) {
            fail("no utf-8 suport");
        }

        new Token(codec, codec.encrypt(badTokenContent));
    }

    @Test(expected = RuntimeException.class)
    public void tooManyUrisTest() {
        final Codec codec = new Codec(Key.generate());

        String badTokenContent = null;
        try {
            badTokenContent += encode("http://example.org", UTF_8.toString()) + ",";
            badTokenContent += encode("http://example.org", UTF_8.toString()) + ",";
            badTokenContent += encode("http://example.org", UTF_8.toString());
        } catch (final UnsupportedEncodingException e) {
            fail("no utf-8 suport");
        }

        new Token(codec, codec.encrypt(badTokenContent));
    }

    @Test
    public void addToUriWithNoParamsTest() {
        final URI initialUri = URI.create("https://fedoraAdmin:moo@127.0.0.1:8080/path#fragment");

        final URI resource = randomUri();

        final URI reference = randomUri();

        final Key key = Key.generate();

        final Codec codec = new Codec(key);

        final Token created = new Token(codec, resource, reference);

        final URI uriWithToken = created.addTo(initialUri);

        assertEquals(initialUri.getScheme(), uriWithToken.getScheme());
        assertEquals(initialUri.getAuthority(), uriWithToken.getAuthority());
        assertEquals(initialUri.getHost(), uriWithToken.getHost());
        assertEquals(initialUri.getPort(), uriWithToken.getPort());
        assertEquals(initialUri.getPath(), uriWithToken.getPath());
        assertEquals(initialUri.getFragment(), uriWithToken.getFragment());
        assertNotEquals(initialUri.getQuery(), uriWithToken.getQuery());

        final Token deserializedFromUrl = new TokenFactory(key).fromUri(uriWithToken);

        assertNotNull(deserializedFromUrl);
        assertEquals(resource, deserializedFromUrl.getPassResource());
        assertEquals(reference, deserializedFromUrl.getReference());

    }

    @Test
    public void addToUriWithParamsTest() {

        final String[] params = { "foo=bar", "baz=huh" };
        final URI initialUri = URI.create("https://fedoraAdmin:moo@127.0.0.1:8080/path?" + String.join("&", params) +
                "#fragment");

        final URI resource = randomUri();

        final URI reference = randomUri();

        final Key key = Key.generate();

        final Codec codec = new Codec(key);

        final Token created = new Token(codec, resource, reference);

        final URI uriWithToken = created.addTo(initialUri);

        assertEquals(initialUri.getScheme(), uriWithToken.getScheme());
        assertEquals(initialUri.getAuthority(), uriWithToken.getAuthority());
        assertEquals(initialUri.getHost(), uriWithToken.getHost());
        assertEquals(initialUri.getPort(), uriWithToken.getPort());
        assertEquals(initialUri.getPath(), uriWithToken.getPath());
        assertEquals(initialUri.getFragment(), uriWithToken.getFragment());
        assertNotEquals(initialUri.getQuery(), uriWithToken.getQuery());

        assertTrue(uriWithToken.getQuery().contains(params[0]));
        assertTrue(uriWithToken.getQuery().contains(params[1]));

        final Token deserializedFromUrl = new TokenFactory(key).fromUri(uriWithToken);

        assertNotNull(deserializedFromUrl);
        assertEquals(resource, deserializedFromUrl.getPassResource());
        assertEquals(reference, deserializedFromUrl.getReference());

    }

    static URI randomUri() {
        return URI.create("urn:uuid:" + UUID.randomUUID().toString());
    }
}

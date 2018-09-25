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
import static org.dataconservancy.pass.authz.usertoken.TokenTest.randomUri;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;

import org.junit.Test;

/**
 * @author apb@jhu.edu
 */
public class TokenFactoryTest {

    @Test
    public void fromEncodedTokenTest() {
        final TokenFactory toTest = new TokenFactory(Key.generate());

        final URI resource = randomUri();

        final URI reference = randomUri();

        final Token token = new Token(toTest.codec, resource, reference);

        final Token fromString = toTest.from(token.toString());

        assertEquals(reference, fromString.getReference());
        assertEquals(resource, fromString.getPassResource());
    }

    @Test
    public void buildTokenTest() {

        final URI resource = randomUri();

        final URI reference = randomUri();

        final TokenFactory toTest = new TokenFactory(Key.generate());

        final Token created = toTest.forPassResource(resource).withReference(reference);

        assertEquals(reference, created.getReference());
        assertEquals(resource, created.getPassResource());
    }

    @Test
    public void initializeWithStringTest() {

        final Key key = Key.generate();

        final TokenFactory factory = new TokenFactory(key.toString());

        final Codec withKnownKey = new Codec(key);

        final String TEST = "test";

        assertEquals(TEST, factory.codec.decrypt(withKnownKey.encrypt(TEST)));

    }

    @Test
    public void fromUriTest() {

        final Key key = Key.generate();

        final TokenFactory toTest = new TokenFactory(key);

        final URI resource = randomUri();

        final URI reference = randomUri();

        final Token token = toTest.forPassResource(resource).withReference(reference);

        final URI uriWithToken = URI.create("https://fedoraAdmin:moo@pass.local:8080/path/to/whatever?" +
                USER_TOKEN_PARAM + "=" + token.toString() + "#part");

        assertTrue(toTest.hasToken(uriWithToken));

        final Token decoded = toTest.fromUri(uriWithToken);

        assertEquals(resource, decoded.getPassResource());
        assertEquals(reference, decoded.getReference());
    }

    @Test
    public void fromUriWithOtherParamsTest() {
        final Key key = Key.generate();

        final TokenFactory toTest = new TokenFactory(key);

        final URI resource = randomUri();

        final URI reference = randomUri();

        final Token token = toTest.forPassResource(resource).withReference(reference);

        final URI uriWithToken = URI.create(
                "https://fedoraAdmin:moo@pass.local:8080/path/to/whatever?whatever=foo&" +
                        USER_TOKEN_PARAM + "=" + token.toString() + "&bar=keep#part");

        assertTrue(toTest.hasToken(uriWithToken));

        final Token decoded = toTest.fromUri(uriWithToken);

        assertEquals(resource, decoded.getPassResource());
        assertEquals(reference, decoded.getReference());
    }

    @Test
    public void fromUriWithNoTokenTest() {
        final Key key = Key.generate();

        final TokenFactory toTest = new TokenFactory(key);

        final URI uriWithToken = URI.create(
                "https://fedoraAdmin:moo@pass.local:8080/path/to/whatever?whatever=foo&bar=whatever#part");

        assertFalse(toTest.hasToken(uriWithToken));
        assertNull(toTest.fromUri(uriWithToken));
    }
}

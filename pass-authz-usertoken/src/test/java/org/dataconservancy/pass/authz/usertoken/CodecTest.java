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

import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;

import org.junit.Test;

/**
 * @author apb@jhu.edu
 */
public class CodecTest {

    final Codec codec = new Codec(Key.generate());

    @Test
    public void roundTripTest() {

        final byte[] buf = new byte[128];
        new SecureRandom().nextBytes(buf);

        final String TEXT = new String(buf);

        assertEquals(TEXT, codec.decrypt(codec.encrypt(TEXT)));
    }

    @Test(expected = RuntimeException.class)
    public void badDataTest() {
        codec.decrypt("NOOO");
    }

    @Test(expected = RuntimeException.class)
    public void truncatedDataTest() {
        final String encrypted = codec.encrypt("Hello");
        codec.decrypt(encrypted.substring(0, encrypted.length() - 1));
    }
}

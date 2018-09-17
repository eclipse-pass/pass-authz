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

import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base32;

/**
 * Represents an encryption key for generating/decoding PASS user tokens.
 *
 * @author apb@jhu.edu
 */
public class Key {

    final byte[] bytes;

    static final Base32 base32 = new Base32();

    /* Internal constructor, given 16-byte key array */
    Key(byte[] bytes) {
        if (!(bytes.length == 16)) {
            throw new IllegalArgumentException("Key must be 16 bytes (128 bits) long, but was given " + bytes.length);
        }

        this.bytes = bytes;
    }

    /**
     * Decode a key from a base32 encoded string.
     *
     * @param key The encoded key string, expected ultimately have originated from {@link Key#toString()}
     * @return The resulting Key.
     */
    public static Key fromString(String key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }

        return new Key(base32.decode(key));
    }

    /**
     * Provide a base32-encoded String representation of the key.
     *
     * @return base32 encoded string.
     */
    @Override
    public String toString() {
        return base32.encodeAsString(bytes);
    }

    /**
     * Generate a new, random, Key
     *
     * @return The new key.
     */
    public static Key generate() {

        final byte[] keyBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);

        return new Key(keyBytes);

    }
}

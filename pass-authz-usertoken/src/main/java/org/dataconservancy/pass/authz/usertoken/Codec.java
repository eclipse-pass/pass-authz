
package org.dataconservancy.pass.authz.usertoken;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

/**
 * Internal class for encrypting/decrypting tokens.
 *
 * @author apb@jhu.edu
 */
class Codec {

    static final SecureRandom random = new SecureRandom();

    static final Base32 base32 = new Base32();

    private final SecretKey key;

    Codec(Key key) {
        this.key = new SecretKeySpec(key.bytes, "AES");
    }

    String encrypt(String content) {

        // Each message gets its own initialization vector.
        final byte[] iv = new byte[12];
        random.nextBytes(iv);

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        } catch (final Exception e) {
            // This means the JVM's security libs don't support the encryption spec.
            throw new RuntimeException("Error initializing token ciper", e);
        }

        // prepend the initialization vector and its length to the message. Yes, it's sent cleartext. But that's what
        // cryptographers say we're supposed to do.
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(iv.length);
            out.write(iv);
        } catch (final IOException e) {
            // This should never happen.
            throw new RuntimeException("Panic: Exception wile writing to a byte array", e);
        }

        // Now the encrypted text
        try {
            out.write(cipher.doFinal(content.getBytes()));
        } catch (final Exception e) {
            // This should never happen
            throw new RuntimeException("Error while writing cipher text", e);
        }

        // Finally, Base32 encode
        return base32.encodeAsString(out.toByteArray()).replaceAll("=", "");
    }

    String decrypt(String encrypted) {

        // Base32 decode.
        final ByteBuffer byteBuffer = ByteBuffer.wrap(base32.decode(encrypted));

        // Get the initialization vector
        final int ivLength = byteBuffer.get();
        final byte[] iv = new byte[ivLength];

        try {
            byteBuffer.get(iv);
        } catch (final BufferUnderflowException e) {
            throw new RuntimeException("Encountered encrypted data that is likely corrupt", e);
        }

        // Get the encrypted bytes
        final byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        // Decrypt and ship as a string
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (final Exception e) {
            // Should never happen unless the JVM's libs don't support the spec
            throw new RuntimeException("Error initializing token cipher");
        }

        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        } catch (final InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Encountered encrypted data that is likely corrupt", e);
        } catch (final InvalidKeyException e) {
            throw new RuntimeException("Bad decryption key", e);
        }

        try {
            return new String(cipher.doFinal(cipherText));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("Encountered encrypted data that is likely corrupt", e);
        }
    }
}

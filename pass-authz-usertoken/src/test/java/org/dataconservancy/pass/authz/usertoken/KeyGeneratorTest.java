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

import static org.junit.Assert.assertNotNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.SystemOutRule;

/**
 * @author apb@jhu.edu
 */
public class KeyGeneratorTest {

    @Rule
    public final SystemOutRule captureSystemOut = new SystemOutRule().enableLog();

    @Test
    public void keyTest() {
        KeyGenerator.main(null);

        // Make sure we can read the resulting key, and use it with the codec
        assertNotNull(new Codec(Key.fromString(captureSystemOut.getLog())).encrypt("Does the key work?"));
    }

}

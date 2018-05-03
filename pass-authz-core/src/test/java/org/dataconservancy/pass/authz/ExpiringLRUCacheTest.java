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

package org.dataconservancy.pass.authz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

/**
 * @author apb@jhu.edu
 */
public class ExpiringLRUCacheTest {

    final String KEY1 = "key1";

    final String KEY2 = "key2";

    final String KEY3 = "key3";

    final String VALUE1 = "value1";

    final String VALUE2 = "value2";

    final String VALUE3 = "value3";

    @Test
    public void capacityTest() {
        final ExpiringLRUCache<String, String> toTest = new ExpiringLRUCache<>(2, Duration.ofSeconds(1));

        toTest.getOrDo(KEY1, () -> VALUE1);
        toTest.getOrDo(KEY2, () -> VALUE2);

        assertEquals(VALUE1, toTest.get(KEY1));
        assertEquals(VALUE2, toTest.get(KEY2));

        toTest.getOrDo(KEY3, () -> VALUE3);
        assertEquals(VALUE2, toTest.get(KEY2));
        assertEquals(VALUE3, toTest.get(KEY3));
        assertNull(toTest.get(KEY1));
    }

    @Test
    public void expiryTest() throws Exception {
        final ExpiringLRUCache<String, String> toTest = new ExpiringLRUCache<>(50, Duration.ofMillis(1));

        toTest.getOrDo(KEY1, () -> VALUE1);
        toTest.getOrDo(KEY2, () -> VALUE2);

        Thread.sleep(75);

        assertNull(toTest.get(KEY1));
        assertNull(toTest.get(KEY2));
    }

    @Test
    public void generateOnlyWhenNecessaryTest() {
        final ExpiringLRUCache<String, Integer> toTest = new ExpiringLRUCache<>(10, Duration.ofSeconds(1));

        final AtomicInteger executionCount = new AtomicInteger(0);

        assertEquals(1, toTest.getOrDo(KEY1, () -> executionCount.incrementAndGet()).intValue());
        assertEquals(1, toTest.getOrDo(KEY1, () -> executionCount.incrementAndGet()).intValue());
        assertEquals(1, toTest.getOrDo(KEY1, () -> executionCount.incrementAndGet()).intValue());

        assertEquals(1, executionCount.get());

    }
}

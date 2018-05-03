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

package org.dataconservancy.pass.authz;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A cache that holds a fixed number of items, for a fixed time.
 * <p>
 * When cache reaches capacity, the oldest entries are evicted. All entries are evicted after a set duration. This is
 * helpful for temporarily caching authorizations that may be expensive to look up.
 * </p>
 *
 * @author apb@jhu.edu
 */
@SuppressWarnings("serial")
public class ExpiringLRUCache<K, V> {

    Logger LOG = LoggerFactory.getLogger(ExpiringLRUCache.class);

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    ExecutorService runner = Executors.newCachedThreadPool();

    final Duration expiry;

    private final Map<K, Future<V>> cache;

    /**
     * Create a cache of the desired size expiration duration for entries.
     *
     * @param capacity Capacity of the cache;
     * @param expiry How long each entry may live in the cache;
     */
    public ExpiringLRUCache(final int capacity, final Duration expiry) {
        cache = new LinkedHashMap<K, Future<V>>(capacity) {

            @Override
            protected boolean removeEldestEntry(Map.Entry<K, Future<V>> eldest) {

                if (size() > capacity) {
                    LOG.info("Cache full, removing oldest entry; {}", eldest.getKey());
                    return true;
                }
                return false;
            }
        };

        this.expiry = expiry;
    }

    /**
     * Get a cached value, or run the provided generator to compute a new value.
     *
     * @param key Retrieval key
     * @param generator Function that MAY be executed, if there is no cached value
     * @return The cached or generated value.
     */
    public V getOrDo(K key, Callable<V> generator) {

        final Future<V> result;
        synchronized (cache) {

            if (cache.containsKey(key)) {
                result = cache.get(key);
            } else {
                result = runner.submit(generator);
                cache.put(key, result);
                scheduler.schedule(() -> {
                    remove(key);
                }, expiry.toMillis(), TimeUnit.MILLISECONDS);
            }
        }
        return doGet(result);
    }

    private void remove(K key) {
        synchronized (cache) {
            cache.remove(key);
        }
    }

    /**
     * Get a cached value, or null if not present in cache.
     *
     * @param key Cache key.
     * @return
     */
    public V get(K key) {
        synchronized (cache) {
            return Optional.ofNullable(cache.get(key)).map(ExpiringLRUCache::doGet).orElse(null);
        }
    }

    private static <V> V doGet(Future<V> value) {
        try {
            return value.get();
        } catch (final ExecutionException e) {
            if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }
}

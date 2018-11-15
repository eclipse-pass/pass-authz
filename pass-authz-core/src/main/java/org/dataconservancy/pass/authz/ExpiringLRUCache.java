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
import java.util.function.BiFunction;
import java.util.function.Function;

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
 * @param <K> Key type
 * @param <V> Value type
 */
@SuppressWarnings("serial")
public class ExpiringLRUCache<K, V> {

    Logger LOG = LoggerFactory.getLogger(ExpiringLRUCache.class);

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    ExecutorService runner = Executors.newCachedThreadPool();

    final Duration expiry;

    private final Map<K, Future<V>> cache;

    private final String name;

    /**
     * Create a cache of the desired size expiration duration for entries.
     *
     * @param capacity Capacity of the cache;
     * @param expiry How long each entry may live in the cache;
     */
    public ExpiringLRUCache(final int capacity, final Duration expiry) {

        name = Thread.currentThread().getStackTrace()[2].getClassName();

        cache = new LinkedHashMap<K, Future<V>>(capacity) {

            @Override
            protected boolean removeEldestEntry(Map.Entry<K, Future<V>> eldest) {

                if (size() > capacity) {
                    LOG.info("[{}] Cache full, removing oldest entry; {}", name, eldest.getKey());
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
        return getOrDo(key, generator, Function.identity());
    }

    /**
     * Get a cached value, or run the provided generator to compute a new value.  The supplied filter will be applied
     * to non-null values.
     *
     * @param key       Retrieval key
     * @param generator Function that MAY be executed, if there is no cached value
     * @param filter    Function applied to non-null values, regardless of whether the value was retrieved from the
     *                  cache
     * @return The cached or generated value after application of the {@code filter}
     */
    public V getOrDo(K key, Callable<V> generator, Function<V, V> filter) {

        final Future<V> result;
        boolean cached = true;
        synchronized (cache) {
            if (cache.containsKey(key)) {
                // get the cached future, and apply the filter to the future's value
                result = runner.submit(() -> {
                    V value = doGet(cache.get(key));
                    return value != null ? filter.apply(value) : null;
                });
                cached = true;
            } else {
                cached = false;
                result = runner.submit(() -> {
                    // call the generator, and apply the filter to the generated future's value
                    final V value = generator.call();
                    LOG.debug("[{}] Calculated value for {} as {}", name, key, value);
                    return value != null ? filter.apply(value) : null;
                });
                cache.put(key, result);
                scheduler.schedule(() -> {
                    LOG.info("[{}] Expiring cached value for {}", name, key);
                    remove(key);
                }, expiry.toMillis(), TimeUnit.MILLISECONDS);
            }
        }

        final V value = doGet(result);
        if (value == null) {
            LOG.info("[{}] Value for key {} is null, refusing to cache it", name, key);
            remove(key);
        } else {
            if (cached) {
                LOG.debug("[{}] Returning cached value for {}: {}", name, key, value);
            } else {
                LOG.debug("[{}] Return calculated value for {}: {}", name, key, value);
            }
        }
        return value;
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
     * @return The cached value
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
            throw new RuntimeException("Read from cache was interrupted");
        }
    }
}

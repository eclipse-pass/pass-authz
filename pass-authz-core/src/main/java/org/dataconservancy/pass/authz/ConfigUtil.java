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

import static java.util.stream.Stream.concat;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class ConfigUtil {

    static final Logger LOG = LoggerFactory.getLogger(ConfigUtil.class);

    /**
     * Creates a stream of all system properties and environment variables in "property normal form".
     * <p>
     * All environment variables and properties are lowercased, and have "_" replaced with ".".
     * </p>
     *
     * @return Stream of all properties
     */
    public static Stream<String> props() {
        return concat(System.getenv().keySet().stream(), System.getProperties().stringPropertyNames().stream())
                .map(ConfigUtil::toPropName);
    }

    /**
     * Return a map of all property suffixes and values that match a given prefix.
     * <p>
     * Searches a stream of property (or environment variable) names for those that begin with a given prefix. When
     * found, it will truncate the prefix, and return a map of the remaining property name part and its value.
     * </p>
     * <p>
     * For example, a property <code>my.lovely.property.abc.123 = myValue</code> will match prefix
     * <code>my.lovely.property</code>, and will result in a map entry with key <code>abc.123</code> and value
     * <code>myValue</code>
     *
     * @param props Stream of property names.
     * @param prefix The prefix used to select and truncate property names.
     * @return map of truncated property names to values.
     */
    public static Map<String, String> extract(Stream<String> props, String prefix) {
        return props
                .filter(key -> key.startsWith(toPropName(prefix)))
                .filter(prop -> getValue(prop) != null)
                .collect(Collectors.toMap(prop -> removePrefix(prefix, prop), prop -> getValue(prop)));
    }

    public static String getValue(String key) {
        return System.getProperty(key, System.getenv(toEnvName(key)));
    }

    static String removePrefix(String prefix, String key) {
        return key.replaceFirst("^" + prefix, "").replaceFirst(".", "");
    }

    public static String toPropName(String name) {
        return name.toLowerCase().replace('_', '.');
    }

    public static String toEnvName(String name) {
        return name.toUpperCase().replace('.', '_');
    }
}

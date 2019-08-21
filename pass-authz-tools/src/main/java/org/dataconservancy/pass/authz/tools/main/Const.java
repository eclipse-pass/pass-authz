/*
 * Copyright 2019 Johns Hopkins University
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
package org.dataconservancy.pass.authz.tools.main;

import java.net.URI;
import java.util.Optional;

import static java.util.Optional.ofNullable;

/**
 * @author Elliot Metsger (emetsger@jhu.edu)
 */
class Const {

    /**
     * Property or environment varialbe containing the base URI for PASS roles, e.g.
     * {@code http://oapass.org/ns/roles/johnshopkins.edu}
     */
    static final String ROLE_BASE_PROP = "pass.authz.rolebase";

    /**
     * Optional base URI provided by {@link #ROLE_BASE_PROP}
     */
    static final Optional<URI> ROLE_BASE_URI = ofNullable(System.getProperties().getProperty(Const.ROLE_BASE_PROP,
            System.getenv(Const.ROLE_BASE_PROP.toUpperCase().replace(".", "_"))))
            .map(uri -> uri.endsWith("#") ? uri : uri + "#")
            .map(URI::create);
}

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

package org.dataconservancy.pass.authz.listener;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * Message about an Resource in Fedora upon which some action has been performed.
 *
 * @author mpatton@jhu.edu
 */
public class FedoraMessage {

    private String res_uri;

    private String[] res_types;

    private FedoraAction action;

    public URI getResourceURI() {
        return URI.create(res_uri);
    }

    public void setResourceURI(String res_uri) {
        this.res_uri = res_uri;
    }

    public List<String> getResourceTypes() {
        return Arrays.asList(res_types);
    }

    public void setResourceTypes(String[] res_types) {
        this.res_types = res_types;
    }

    public FedoraAction getAction() {
        return action;
    }

    public void setAction(FedoraAction action) {
        this.action = action;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((action == null) ? 0 : action.hashCode());
        result = prime * result + Arrays.hashCode(res_types);
        result = prime * result + ((res_uri == null) ? 0 : res_uri.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final FedoraMessage other = (FedoraMessage) obj;
        if (action != other.action) {
            return false;
        }
        if (!Arrays.equals(res_types, other.res_types)) {
            return false;
        }
        if (res_uri == null) {
            if (other.res_uri != null) {
                return false;
            }
        } else if (!res_uri.equals(other.res_uri)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return action + " " + res_uri;
    }
}

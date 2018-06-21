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

package org.dataconservancy.pass.authz.tools;

import java.util.stream.Stream;

import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.TextMessage;

import org.json.JSONArray;
import org.json.JSONObject;

// TODO Give good error messages on unexpected json?

public class FedoraMessageConverter {
    private static final String DELETION = "http://fedora.info/definitions/v4/event#ResourceDeletion";
    private static final String MODIFICATION = "http://fedora.info/definitions/v4/event#ResourceModification";
    private static final String CREATION = "http://fedora.info/definitions/v4/event#ResourceCreation";

    public static FedoraMessage convert(Message m) throws JMSException {
        return convert(TextMessage.class.cast(m).getText());
    }

    private static boolean contains(String[] array, String s) {
        return Stream.of(array).anyMatch(s::equals);
    }

    public static FedoraMessage convert(String text) {
        JSONObject root = new JSONObject(text);

        String uri = root.getString("id");

        JSONArray types_array = root.getJSONArray("type");

        String[] types = to_string_array(types_array);

        JSONObject gen = root.getJSONObject("wasGeneratedBy");

        JSONArray actions_array = gen.getJSONArray("type");

        String[] actions = to_string_array(actions_array);
        FedoraAction action = null;

        // May have MODIFIED with both CREATION and DELETION
        // Give precedence to CREATION and DELETION

        if (contains(actions, CREATION)) {
            action = FedoraAction.CREATED;
        } else if (contains(actions, DELETION)) {
            action = FedoraAction.DELETED;
        } else if (contains(actions, MODIFICATION)) {
            action = FedoraAction.MODIFIED;
        }

        FedoraMessage result = new FedoraMessage();

        result.setResourceURI(uri);
        result.setResourceTypes(types);
        result.setAction(action);

        return result;
    }

    private static String[] to_string_array(JSONArray json) {
        String[] result = new String[json.length()];

        for (int i = 0; i < json.length(); i++) {
            result[i] = json.getString(i);
        }

        return result;
    }
}

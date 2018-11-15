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

import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

/**
 * Provides details about authenticated users given an http request.
 *
 * @author apb@jhu.edu
 */
public interface AuthUserProvider {

    /**
     * Get the authenticated user from the current http request.
     * <p>
     * Inspects the http request for the current user/principal, and provides information about that user
     * <p>
     *
     * @param request the current http request.
     * @return the AuthUser
     */
    public default AuthUser getUser(HttpServletRequest request) {
        return getUser(request, a -> a, true);
    }

    /**
     * Get the authenticated user, and filter the result before returning.
     * <p>
     * Inspects the http request for the current user/principal, and provides information about that user. Invokes the
     * provided function to map/transform/inspect the authenticated user. The primary use case is filter for "create
     * if not present".
     * <p>
     *
     * @param request HTTP request
     * @param filterWhenDone Function to be applied to the authUser.
     * @param allowCached If true, then the implementation may return a cached result (this potentially NOT executing
     *        the function). Otherwise, if false, the implementation MAY cache the result. But if it does, it MUST
     *        cache the result AFTER having applied the provided function.
     * @return the AuthUser.
     */
    public AuthUser getUser(HttpServletRequest request, Function<AuthUser, AuthUser> filterWhenDone,
            boolean allowCached);
}

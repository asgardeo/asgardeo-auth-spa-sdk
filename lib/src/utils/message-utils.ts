/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { ResponseMessage } from "../models";

export class MessageUtils {

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() { }

    /**
     * JSON stringifies the passed object.
     *
     * @param {any} data The data object.
     *
     * @return {ResponseMessage<string>} JSON string.
     */
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    public static generateSuccessMessage(data?: any): ResponseMessage<string>{
        return {
            blob: data?.data instanceof Blob ? data?.data : null,
            data: JSON.stringify(data ?? ""),
            success: true
        };
    }

    /**
     *
     * Explicitly constructs a serializable error shape instead of relying on
     * JSON.stringify(error) directly. This is necessary because axios 1.x defines
     * toJSON() on the AxiosError prototype which deliberately excludes `response`
     * (to avoid leaking sensitive data). Since toJSON() is on the prototype and not
     * the instance, `delete error.toJSON` is a no-op, and JSON.stringify ends up
     * calling the prototype's toJSON — stripping response.data (and server-side
     * error codes like BPM-60006) from the postMessage payload.
     *
     * @param {any} error The error object.
     *
     * @return {ResponseMessage<string>} JSON string.
     */
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    public static generateFailureMessage(error?: any): ResponseMessage<string> {
        const serializable: any = error ? {
            code: error?.code,
            config: error?.config,
            isAxiosError: error?.isAxiosError,
            message: error?.message,
            name: error?.name,
            request: error?.request,
            response: error?.response ? {
                config: error.response.config,
                data: error.response.data,
                headers: error.response.headers,
                request: error.response.request,
                status: error.response.status,
                statusText: error.response.statusText
            } : undefined,
            status: error?.status ?? error?.response?.status ?? null
        } : "";

        return {
            error: JSON.stringify(serializable),
            success: false
        };
    }
}

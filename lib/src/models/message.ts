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

import {
    AUTH_CODE,
    CHECK_SESSION_SIGNED_IN,
    CHECK_SESSION_SIGNED_OUT,
    DISABLE_HTTP_HANDLER,
    ENABLE_HTTP_HANDLER,
    END_USER_SESSION,
    GET_AUTH_URL,
    GET_BASIC_USER_INFO,
    GET_CONFIG_DATA,
    GET_CRYPTO_HELPER,
    GET_DECODED_IDP_ID_TOKEN,
    GET_DECODED_ID_TOKEN,
    GET_ID_TOKEN,
    GET_OIDC_SERVICE_ENDPOINTS,
    GET_SIGN_OUT_URL,
    HTTP_REQUEST,
    HTTP_REQUEST_ALL,
    INIT,
    IS_AUTHENTICATED,
    REFRESH_ACCESS_TOKEN,
    REQUEST_ACCESS_TOKEN,
    REQUEST_CUSTOM_GRANT,
    REQUEST_ERROR,
    REQUEST_FINISH,
    REQUEST_START,
    REQUEST_SUCCESS,
    REVOKE_ACCESS_TOKEN,
    SET_SESSION_STATE,
    SET_SESSION_STATE_FROM_IFRAME,
    SIGN_IN,
    SIGN_OUT,
    START_AUTO_REFRESH_TOKEN,
    UPDATE_CONFIG
} from "../constants";

export interface ResponseMessage<T> {
    success: boolean;
    error?: string;
    data?: T;
    blob?: Blob;
}

export interface Message<T> {
    type: MessageType;
    data?: T;
}

export interface AuthorizationInfo {
    code: string;
    sessionState: string;
    pkce?: string;
    state: string;
}

export type MessageType =
    | typeof INIT
    | typeof SIGN_IN
    | typeof AUTH_CODE
    | typeof SIGN_OUT
    | typeof HTTP_REQUEST
    | typeof HTTP_REQUEST_ALL
    | typeof REQUEST_CUSTOM_GRANT
    | typeof REVOKE_ACCESS_TOKEN
    | typeof END_USER_SESSION
    | typeof REQUEST_ERROR
    | typeof REQUEST_FINISH
    | typeof REQUEST_START
    | typeof REQUEST_SUCCESS
    | typeof GET_OIDC_SERVICE_ENDPOINTS
    | typeof GET_BASIC_USER_INFO
    | typeof GET_DECODED_ID_TOKEN
    | typeof GET_CRYPTO_HELPER
    | typeof GET_DECODED_IDP_ID_TOKEN
    | typeof ENABLE_HTTP_HANDLER
    | typeof DISABLE_HTTP_HANDLER
    | typeof GET_AUTH_URL
    | typeof REQUEST_ACCESS_TOKEN
    | typeof IS_AUTHENTICATED
    | typeof GET_SIGN_OUT_URL
    | typeof REFRESH_ACCESS_TOKEN
    | typeof SET_SESSION_STATE
    | typeof START_AUTO_REFRESH_TOKEN
    | typeof UPDATE_CONFIG
    | typeof GET_ID_TOKEN
    | typeof CHECK_SESSION_SIGNED_IN
    | typeof CHECK_SESSION_SIGNED_OUT
    | typeof GET_CONFIG_DATA
    | typeof SET_SESSION_STATE_FROM_IFRAME;

export interface CommunicationHelperInterface {
    communicate: <T, R>(message: Message<T>) => Promise<R>;
}

export interface AuthorizationResponse {
    authorizationURL: string;
    pkce?: string;
}

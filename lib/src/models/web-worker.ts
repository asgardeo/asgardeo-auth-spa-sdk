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
    AuthClientConfig,
    AuthorizationURLParams,
    BasicUserInfo,
    CryptoHelper,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    FetchResponse,
    OIDCEndpoints
} from "@asgardeo/auth-js";
import { HttpRequestConfig, HttpResponse, Message } from ".";
import { AuthorizationResponse, WebWorkerClientConfig } from "..";

interface WebWorkerEvent<T> extends MessageEvent {
    data: Message<T>;
}

export class WebWorkerClass<T> extends Worker {
    public onmessage: (this: Worker, event: WebWorkerEvent<T>) => any = () => null;
}

export interface WebWorkerCoreInterface {
    setHttpRequestStartCallback(callback: () => void): void;
    setHttpRequestSuccessCallback(callback: (response: HttpResponse) => void): void;
    setHttpRequestFinishCallback(callback: () => void): void;
    httpRequest(config: HttpRequestConfig): Promise<HttpResponse>;
    httpRequestAll(configs: HttpRequestConfig[]): Promise<HttpResponse[] | undefined>;
    enableHttpHandler(): void;
    disableHttpHandler(): void;
    getAuthorizationURL(params?: AuthorizationURLParams, signInRedirectURL?: string): Promise<AuthorizationResponse>;
    requestAccessToken(
        authorizationCode?: string,
        sessionState?: string,
        pkce?: string,
        state?: string
    ): Promise<BasicUserInfo>;
    signOut(signOutRedirectURL?: string): Promise<string>;
    getSignOutURL(signOutRedirectURL?: string): Promise<string>;
    requestCustomGrant(config: CustomGrantConfig): Promise<BasicUserInfo | FetchResponse>;
    refreshAccessToken(): Promise<BasicUserInfo>;
    revokeAccessToken(): Promise<boolean>;
    getBasicUserInfo(): Promise<BasicUserInfo>;
    getDecodedIDToken(): Promise<DecodedIDTokenPayload>;
    getDecodedIDPIDToken(): Promise<DecodedIDTokenPayload>;
    getCryptoHelper(): Promise<CryptoHelper>;
    getIDToken(): Promise<string>;
    getOIDCServiceEndpoints(): Promise<OIDCEndpoints>;
    getAccessToken(): Promise<string>;
    isAuthenticated(): Promise<boolean>;
    startAutoRefreshToken(): Promise<void>;
    setSessionState(sessionState: string): Promise<void>;
    updateConfig(config: Partial<AuthClientConfig<WebWorkerClientConfig>>): Promise<void>;
    getConfigData(): Promise<AuthClientConfig<WebWorkerClientConfig>>;
}

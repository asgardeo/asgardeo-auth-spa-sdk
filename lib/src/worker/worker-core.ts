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
    AsgardeoAuthClient,
    AuthClientConfig,
    AuthorizationURLParams,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    FetchResponse,
    OIDCEndpoints,
    SESSION_STATE,
    STATE,
    Store
} from "@asgardeo/auth-js";
import { AuthenticationHelper, SPAHelper } from "../helpers";
import { HttpClient, HttpClientInstance } from "../http-client";
import {
    AuthorizationResponse,
    HttpRequestConfig,
    HttpResponse,
    WebWorkerClientConfig,
    WebWorkerCoreInterface
} from "../models";
import { MemoryStore } from "../stores";
import { SPACryptoUtils } from "../utils/crypto-utils";

export const WebWorkerCore = async (
    config: AuthClientConfig<WebWorkerClientConfig>,
    getAuthHelper: (
        authClient: AsgardeoAuthClient<WebWorkerClientConfig>,
        spaHelper: SPAHelper<WebWorkerClientConfig>
    ) => AuthenticationHelper<WebWorkerClientConfig>
): Promise<WebWorkerCoreInterface> => {
    const _store: Store = new MemoryStore();
    const _cryptoUtils: SPACryptoUtils = new SPACryptoUtils();
    const _authenticationClient = new AsgardeoAuthClient<WebWorkerClientConfig>(_store, _cryptoUtils);
    await _authenticationClient.initialize(config);

    const _spaHelper = new SPAHelper<WebWorkerClientConfig>(_authenticationClient);

    const _authenticationHelper: AuthenticationHelper<WebWorkerClientConfig> = 
        getAuthHelper(_authenticationClient, _spaHelper);

    const _dataLayer = _authenticationClient.getDataLayer();

    const _httpClient: HttpClientInstance = HttpClient.getInstance();

    const attachToken = async (request: HttpRequestConfig): Promise<void> => {
        const requestConfig = { attachToken: true, ...request };
        if (requestConfig.attachToken) {
            request.headers = {
                ...request.headers,
                Authorization: `Bearer ${ await _authenticationHelper.getAccessToken() }`
            };
        }
    };

    _httpClient?.init && (await _httpClient.init(true, attachToken));

    const setHttpRequestStartCallback = (callback: () => void): void => {
        _httpClient?.setHttpRequestStartCallback && _httpClient.setHttpRequestStartCallback(callback);
    };

    const setHttpRequestSuccessCallback = (callback: (response: HttpResponse) => void): void => {
        _httpClient?.setHttpRequestSuccessCallback && _httpClient.setHttpRequestSuccessCallback(callback);
    };

    const setHttpRequestFinishCallback = (callback: () => void): void => {
        _httpClient?.setHttpRequestFinishCallback && _httpClient.setHttpRequestFinishCallback(callback);
    };
    
    const httpRequest = async (
        requestConfig: HttpRequestConfig
    ): Promise<HttpResponse> => {
        return await _authenticationHelper.httpRequest(
          _httpClient,
          requestConfig
        );
    };

    const httpRequestAll = async (requestConfigs: HttpRequestConfig[]): Promise<HttpResponse[] | undefined> => {
        return await _authenticationHelper.httpRequestAll(
            requestConfigs,
            _httpClient
        );
    };

    const enableHttpHandler = (): void => {
        _authenticationHelper.enableHttpHandler(_httpClient);
    };

    const disableHttpHandler = (): void => {
        _authenticationHelper.disableHttpHandler(_httpClient);
    };

    const getAuthorizationURL = async (params?: AuthorizationURLParams): Promise<AuthorizationResponse> => {
        return _authenticationClient
            .getAuthorizationURL(params)
            .then(async (url: string) => {
                const urlObject: URL = new URL(url);
                const state: string = urlObject.searchParams.get(STATE) ?? "";
                const pkce: string = await _authenticationClient.getPKCECode(state);

                return { authorizationURL: url, pkce: pkce };
            })
            .catch((error) => Promise.reject(error));
    };

    const startAutoRefreshToken = async (): Promise<void> => {
        _spaHelper.clearRefreshTokenTimeout();
        _spaHelper.refreshAccessTokenAutomatically();

        return;
    };

    const requestAccessToken = async (
        authorizationCode?: string,
        sessionState?: string,
        pkce?: string,
        state?: string
    ): Promise<BasicUserInfo> => {
        return await _authenticationHelper.requestAccessToken(
            authorizationCode,
            sessionState,
            undefined,
            pkce,
            state
        );
    };

    const signOut = async (): Promise<string> => {
        _spaHelper.clearRefreshTokenTimeout();

        return await _authenticationClient.signOut();
    };

    const getSignOutURL = async (): Promise<string> => {
        return await _authenticationClient.getSignOutURL();
    };

    const requestCustomGrant = async (config: CustomGrantConfig): Promise<BasicUserInfo | FetchResponse> => {
        return await _authenticationHelper.requestCustomGrant(config);
    };

    const refreshAccessToken = async (): Promise<BasicUserInfo> => {
        try {
            return await _authenticationHelper.refreshAccessToken();
        } catch (error) {
            return Promise.reject(error);
        }
    };

    const revokeAccessToken = (): Promise<boolean> => {
        return _authenticationClient
            .revokeAccessToken()
            .then(() => {
                _spaHelper.clearRefreshTokenTimeout();

                return Promise.resolve(true);
            })
            .catch((error) => Promise.reject(error));
    };

    const getBasicUserInfo = async (): Promise<BasicUserInfo> => {
        return _authenticationHelper.getBasicUserInfo();
    };

    const getDecodedIDToken = async (): Promise<DecodedIDTokenPayload> => {
        return _authenticationHelper.getDecodedIDToken();
    };

    const getIDToken = async (): Promise<string> => {
        return _authenticationHelper.getIDToken();
    };
    const getOIDCServiceEndpoints = async (): Promise<OIDCEndpoints> => {
        return _authenticationHelper.getOIDCServiceEndpoints();
    };

    const getAccessToken = (): Promise<string> => {
        return _authenticationHelper.getAccessToken();
    };

    const isAuthenticated = (): Promise<boolean> => {
        return _authenticationHelper.isAuthenticated();
    };

    const setSessionState = async (sessionState: string): Promise<void> => {
        await _dataLayer.setSessionDataParameter(SESSION_STATE, sessionState);

        return;
    };

    const updateConfig = async (config: Partial<AuthClientConfig<WebWorkerClientConfig>>): Promise<void> => {
        await _authenticationClient.updateConfig(config);

        return;
    };

    const getConfigData = async (): Promise<AuthClientConfig<WebWorkerClientConfig>> => {
        return _dataLayer.getConfigData();
    };

    return {
        disableHttpHandler,
        enableHttpHandler,
        getAccessToken,
        getAuthorizationURL,
        getBasicUserInfo,
        getConfigData,
        getDecodedIDToken,
        getIDToken,
        getOIDCServiceEndpoints,
        getSignOutURL,
        httpRequest,
        httpRequestAll,
        isAuthenticated,
        refreshAccessToken,
        requestAccessToken,
        requestCustomGrant,
        revokeAccessToken,
        setHttpRequestFinishCallback,
        setHttpRequestStartCallback,
        setHttpRequestSuccessCallback,
        setSessionState,
        signOut,
        startAutoRefreshToken,
        updateConfig
    };
};

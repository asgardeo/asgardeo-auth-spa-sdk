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
    AUTHORIZATION_CODE,
    AsgardeoAuthClient,
    AuthClientConfig,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    GetAuthURLConfig,
    OIDCEndpoints,
    PKCE_CODE_VERIFIER,
    ResponseMode,
    SESSION_STATE,
    Store,
    TokenResponse
} from "@asgardeo/auth-js";
import { ERROR, ERROR_DESCRIPTION, Storage } from "../constants";
import { AsgardeoSPAException } from "../exception";
import { SPAHelper, SessionManagementHelper } from "../helpers";
import { HttpClient, HttpClientInstance } from "../http-client";
import {
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    MainThreadClientConfig,
    MainThreadClientInterface
} from "../models";
import { LocalStore, MemoryStore, SessionStore } from "../stores";
import { SPAUtils } from "../utils";

const initiateStore = (store: Storage | undefined): Store => {
    switch (store) {
        case Storage.LocalStorage:
            return new LocalStore();
        case Storage.SessionStorage:
            return new SessionStore();
        case Storage.BrowserMemory:
            return new MemoryStore();
        default:
            return new SessionStore();
    }
};

export const MainThreadClient = async (
    config: AuthClientConfig<MainThreadClientConfig>
): Promise<MainThreadClientInterface> => {
    const _store: Store = initiateStore(config.storage);
    const _authenticationClient = new AsgardeoAuthClient<MainThreadClientConfig>(_store);
    await _authenticationClient.initialize(config);

    const _spaHelper = new SPAHelper<MainThreadClientConfig>(_authenticationClient);
    const _dataLayer = _authenticationClient.getDataLayer();
    const _sessionManagementHelper = SessionManagementHelper();

    const _httpClient: HttpClientInstance = HttpClient.getInstance();

    const attachToken = async (request: HttpRequestConfig): Promise<void> => {
        request.headers = {
            ...request.headers,
            Authorization: `Bearer ${await _authenticationClient.getAccessToken()}`
        };
    };

    _httpClient?.init && await _httpClient.init(true, attachToken);

    const setHttpRequestStartCallback = (callback: () => void): void => {
        _httpClient?.setHttpRequestStartCallback && _httpClient.setHttpRequestStartCallback(callback);
    };

    const setHttpRequestSuccessCallback = (callback: (response: HttpResponse) => void): void => {
        _httpClient?.setHttpRequestSuccessCallback && _httpClient.setHttpRequestSuccessCallback(callback);
    };

    const setHttpRequestFinishCallback = (callback: () => void): void => {
        _httpClient?.setHttpRequestFinishCallback &&  _httpClient.setHttpRequestFinishCallback(callback);
    };

    const setHttpRequestErrorCallback = (callback: (error: HttpError) => void): void => {
        _httpClient?.setHttpRequestErrorCallback && _httpClient.setHttpRequestErrorCallback(callback);
    };

    const httpRequest = (config: HttpRequestConfig): Promise<HttpResponse> => {
        return _httpClient.request(config);
    };

    const httpRequestAll = (config: HttpRequestConfig[]): Promise<HttpResponse[]> | undefined => {
        const requests: Promise<HttpResponse<any>>[] = [];
        config.forEach((request) => {
            requests.push(_httpClient.request(request));
        });

        return _httpClient.all && _httpClient.all(requests);
    };

    const getHttpClient = (): HttpClientInstance => {
        return _httpClient;
    };

    const enableHttpHandler = (): boolean => {
        _httpClient?.enableHandler && _httpClient.enableHandler();

        return true;
    };

    const disableHttpHandler = (): boolean => {
        _httpClient?.disableHandler && _httpClient.disableHandler();

        return true;
    };

    const checkSession = async (): Promise<void> => {
        const oidcEndpoints: OIDCEndpoints = await _authenticationClient.getOIDCServiceEndpoints();

        _sessionManagementHelper.initialize(
            config.clientID,
            oidcEndpoints.checkSessionIframe ?? "",
            (await _authenticationClient.getBasicUserInfo()).sessionState,
            config.checkSessionInterval ?? 3,
            config.sessionRefreshInterval ?? 300,
            config.signInRedirectURL,
            oidcEndpoints.authorizationEndpoint ?? "",
            async () => {
                return _authenticationClient.signOut();
            }
        );
    };

    const signIn = async (
        signInConfig?: GetAuthURLConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo> => {
        const isLoggingOut = await _sessionManagementHelper
            .receivePromptNoneResponse(async (sessionState: string | null) => {
            await _dataLayer.setSessionDataParameter(SESSION_STATE, sessionState ?? "");
            return;
        });

        if (isLoggingOut) {
            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                tenantDomain: "",
                username: ""
            });
        }
        if (await _authenticationClient.isAuthenticated()) {
            _spaHelper.clearRefreshTokenTimeout();
            _spaHelper.refreshAccessTokenAutomatically();
            checkSession();

            return Promise.resolve(await _authenticationClient.getBasicUserInfo());
        }

        let resolvedAuthorizationCode: string;
        let resolvedSessionState: string;

        if (config?.responseMode === ResponseMode.formPost && authorizationCode && sessionState) {
            resolvedAuthorizationCode = authorizationCode;
            resolvedSessionState = sessionState;
        } else {
            resolvedAuthorizationCode = new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE) ?? "";
            resolvedSessionState = new URL(window.location.href).searchParams.get(SESSION_STATE) ?? "";
            SPAUtils.removeAuthorizationCode();
        }

        if (resolvedAuthorizationCode && resolvedSessionState) {
            if (config.storage === Storage.BrowserMemory) {
                const pkce = SPAUtils.getPKCE();

                await _dataLayer.setTemporaryDataParameter(PKCE_CODE_VERIFIER, pkce);
            }

            return _authenticationClient
                .requestAccessToken(resolvedAuthorizationCode, resolvedSessionState)
                .then(async () => {
                    if (config.storage === Storage.BrowserMemory) {
                        SPAUtils.setSignOutURL(await _authenticationClient.getSignOutURL());
                    }

                    _spaHelper.clearRefreshTokenTimeout();
                    _spaHelper.refreshAccessTokenAutomatically();
                    checkSession();

                    return _authenticationClient.getBasicUserInfo();
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        const error = new URL(window.location.href).searchParams.get(ERROR);
        const errorDescription = new URL(window.location.href).searchParams.get(ERROR_DESCRIPTION);

        if (error) {
            const url = new URL(window.location.href);
            url.searchParams.delete(ERROR);
            url.searchParams.delete(ERROR_DESCRIPTION);

            history.pushState(null, document.title, url.toString());

            return Promise.reject(
                new AsgardeoSPAException(
                    "MAIN_THREAD_CLIENT-SI-BE",
                    "main-thread-client",
                    "signIn",
                    error,
                    errorDescription ?? ""
                )
            );
        }

        return _authenticationClient.getAuthorizationURL(signInConfig).then(async (url: string) => {
            if (config.storage === Storage.BrowserMemory) {
                SPAUtils.setPKCE((await _dataLayer.getTemporaryDataParameter(PKCE_CODE_VERIFIER)) as string);
            }

            location.href = url;

            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                tenantDomain: "",
                username: ""
            });
        });
    };

    const signOut = async (): Promise<boolean> => {
        if (await _authenticationClient.isAuthenticated()) {
            location.href = await _authenticationClient.signOut();
        } else {
            location.href = SPAUtils.getSignOutURL();
        }

        _spaHelper.clearRefreshTokenTimeout();

        return true;
    };

    const requestCustomGrant = (config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse> => {
        return _authenticationClient
            .requestCustomGrant(config)
            .then(async (response: HttpResponse | TokenResponse) => {
                if (config.returnsSession) {
                    _spaHelper.refreshAccessTokenAutomatically();

                    return _authenticationClient.getBasicUserInfo();
                } else {
                    return response as HttpResponse;
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const refreshAccessToken = (): Promise<BasicUserInfo> => {
        return _authenticationClient
            .refreshAccessToken()
            .then(() => {
                _spaHelper.refreshAccessTokenAutomatically();

                return _authenticationClient.getBasicUserInfo();
            })
            .catch((error) => {
                return Promise.reject(error);
            });
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
        return _authenticationClient.getBasicUserInfo();
    };

    const getDecodedIDToken = async (): Promise<DecodedIDTokenPayload> => {
        return _authenticationClient.getDecodedIDToken();
    };

    const getIDToken = async (): Promise<string> => {
        return _authenticationClient.getIDToken();
    };

    const getOIDCServiceEndpoints = async (): Promise<OIDCEndpoints> => {
        return _authenticationClient.getOIDCServiceEndpoints();
    };

    const getAccessToken = async (): Promise<string> => {
        return _authenticationClient.getAccessToken();
    };

    const isAuthenticated = async (): Promise<boolean> => {
        return _authenticationClient.isAuthenticated();
    };

    const updateConfig = async (newConfig: Partial<AuthClientConfig<MainThreadClientConfig>>): Promise<void> => {
        config = { ...config, ...newConfig };
        await _authenticationClient.updateConfig(config);
    };

    return {
        disableHttpHandler,
        enableHttpHandler,
        getAccessToken,
        getBasicUserInfo,
        getDecodedIDToken,
        getHttpClient,
        getIDToken,
        getOIDCServiceEndpoints,
        httpRequest,
        httpRequestAll,
        isAuthenticated,
        refreshAccessToken,
        requestCustomGrant,
        revokeAccessToken,
        setHttpRequestErrorCallback,
        setHttpRequestFinishCallback,
        setHttpRequestStartCallback,
        setHttpRequestSuccessCallback,
        signIn,
        signOut,
        updateConfig
    };
};

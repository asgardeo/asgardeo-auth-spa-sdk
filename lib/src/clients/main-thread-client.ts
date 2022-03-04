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
    AuthenticationUtils,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    FetchResponse,
    GetAuthURLConfig,
    OIDCEndpoints,
    ResponseMode,
    SESSION_STATE,
    STATE,
    Store,
    TokenResponse
} from "@asgardeo/auth-js";
import {
    ACCESS_TOKEN_INVALID,
    CHECK_SESSION_SIGNED_IN,
    CHECK_SESSION_SIGNED_OUT,
    CUSTOM_GRANT_CONFIG,
    ERROR,
    ERROR_DESCRIPTION,
    PROMPT_NONE_IFRAME,
    RP_IFRAME,
    SILENT_SIGN_IN_STATE,
    Storage
} from "../constants";
import { AsgardeoSPAException } from "../exception";
import { SPAHelper, SessionManagementHelper } from "../helpers";
import { HttpClient, HttpClientInstance } from "../http-client";
import {
    AuthorizationInfo,
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    MainThreadClientConfig,
    MainThreadClientInterface,
    Message
} from "../models";
import { SPACustomGrantConfig } from "../models/request-custom-grant";
import { LocalStore, MemoryStore, SessionStore } from "../stores";
import { SPAUtils } from "../utils";
import { SPACryptoUtils } from "../utils/crypto-utils";

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
    const _cryptoUtils: SPACryptoUtils = new SPACryptoUtils();
    const _authenticationClient = new AsgardeoAuthClient<MainThreadClientConfig>(_store, _cryptoUtils);
    await _authenticationClient.initialize(config);

    const _spaHelper = new SPAHelper<MainThreadClientConfig>(_authenticationClient);
    const _dataLayer = _authenticationClient.getDataLayer();
    const _sessionManagementHelper = await SessionManagementHelper(
        async () => {
            return _authenticationClient.signOut();
        },
        config.storage ?? Storage.SessionStorage,
        (sessionState: string) => _dataLayer.setSessionDataParameter(SESSION_STATE, sessionState ?? "")
    );

    let _getSignOutURLFromSessionStorage: boolean = false;

    const _httpClient: HttpClientInstance = HttpClient.getInstance();
    let _isHttpHandlerEnabled: boolean = true;
    let _httpErrorCallback: (error: HttpError) => void | Promise<void>;
    let _httpFinishCallback: () => void;

    const attachToken = async (request: HttpRequestConfig): Promise<void> => {
        const requestConfig = { attachToken: true, ...request };
        if (requestConfig.attachToken) {
            request.headers = {
                ...request.headers,
                Authorization: `Bearer ${await _authenticationClient.getAccessToken()}`
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
        _httpFinishCallback = callback;
    };

    const setHttpRequestErrorCallback = (callback: (error: HttpError) => void | Promise<void>): void => {
        _httpErrorCallback = callback;
    };

    const httpRequest = async (requestConfig: HttpRequestConfig): Promise<HttpResponse> => {
        let matches = false;
        const config = await _dataLayer.getConfigData();

        for (const baseUrl of [...((await config?.resourceServerURLs) ?? []), config?.serverOrigin]) {
            if (requestConfig?.url?.startsWith(baseUrl)) {
                matches = true;

                break;
            }
        }

        if (matches) {
            return _httpClient
                .request(requestConfig)
                .then((response: HttpResponse) => {
                    return Promise.resolve(response);
                })
                .catch(async (error: HttpError) => {
                    if (error?.response?.status === 401 || !error?.response) {
                        // Try to refresh the token
                        let refreshTokenResponse;
                        try {
                            refreshTokenResponse = await refreshAccessToken();
                        } catch (refreshError: any) {
                            if (_isHttpHandlerEnabled) {
                                if (typeof _httpErrorCallback === "function") {
                                    await _httpErrorCallback({ ...error, code: ACCESS_TOKEN_INVALID });
                                }
                                if (typeof _httpFinishCallback === "function") {
                                    _httpFinishCallback();
                                }
                            }

                            return Promise.reject(
                                new AsgardeoSPAException(
                                    "MAIN_THREAD_CLIENT-HR-ES01",
                                    "main-thread-client",
                                    "httpRequest",
                                    "",
                                    "",
                                    refreshError
                                )
                            );
                        }

                        // Retry the request after refreshing the token
                        if (refreshTokenResponse) {
                            try {
                                const httpResponse = await _httpClient.request(requestConfig);
                                return Promise.resolve(httpResponse);
                            } catch (error: any) {
                                if (_isHttpHandlerEnabled) {
                                    if (typeof _httpErrorCallback === "function") {
                                        await _httpErrorCallback(error);
                                    }
                                    if (typeof _httpFinishCallback === "function") {
                                        _httpFinishCallback();
                                    }
                                }

                                return Promise.reject(error);
                            }
                        }
                    }

                    if (_isHttpHandlerEnabled) {
                        if (typeof _httpErrorCallback === "function") {
                            await _httpErrorCallback(error);
                        }
                        if (typeof _httpFinishCallback === "function") {
                            _httpFinishCallback();
                        }
                    }

                    return Promise.reject(error);
                });
        } else {
            return Promise.reject(
                new AsgardeoSPAException(
                    "MAIN_THREAD_CLIENT-HR-IV02",
                    "main-thread-client",
                    "httpRequest",
                    "Request to the provided endpoint is prohibited.",
                    "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                        " attribute while initializing the SDK. The specified endpoint in this request " +
                        "cannot be found among the `resourceServerURLs`"
                )
            );
        }
    };

    const httpRequestAll = async (requestConfigs: HttpRequestConfig[]): Promise<HttpResponse[] | undefined> => {
        let matches = true;
        const config = await _dataLayer.getConfigData();

        for (const requestConfig of requestConfigs) {
            let urlMatches = false;

            for (const baseUrl of [...((await config)?.resourceServerURLs ?? []), config?.serverOrigin]) {
                if (requestConfig.url?.startsWith(baseUrl)) {
                    urlMatches = true;

                    break;
                }
            }

            if (!urlMatches) {
                matches = false;

                break;
            }
        }

        const requests: Promise<HttpResponse<any>>[] = [];

        if (matches) {
            requestConfigs.forEach((request) => {
                requests.push(_httpClient.request(request));
            });

            return (
                _httpClient?.all &&
                _httpClient
                    .all(requests)
                    .then((responses: HttpResponse[]) => {
                        return Promise.resolve(responses);
                    })
                    .catch(async (error: HttpError) => {
                        if (error?.response?.status === 401 || !error?.response) {
                            let refreshTokenResponse;
                            try {
                                refreshTokenResponse = await _authenticationClient.refreshAccessToken();
                            } catch (refreshError: any) {
                                if (_isHttpHandlerEnabled) {
                                    if (typeof _httpErrorCallback === "function") {
                                        await _httpErrorCallback({ ...error, code: ACCESS_TOKEN_INVALID });
                                    }
                                    if (typeof _httpFinishCallback === "function") {
                                        _httpFinishCallback();
                                    }
                                }

                                return Promise.reject(
                                    new AsgardeoSPAException(
                                        "MAIN_THREAD_CLIENT-HRA-ES01",
                                        "main-thread-client",
                                        "httpRequestAll",
                                        "",
                                        "",
                                        refreshError
                                    )
                                );
                            }

                            if (refreshTokenResponse) {
                                return _httpClient.all &&
                                    _httpClient
                                        .all(requests)
                                        .then((response) => {
                                            return Promise.resolve(response);
                                        })
                                        .catch(async (error) => {
                                            if (_isHttpHandlerEnabled) {
                                                if (typeof _httpErrorCallback === "function") {
                                                    await _httpErrorCallback(error);
                                                }
                                                if (typeof _httpFinishCallback === "function") {
                                                    _httpFinishCallback();
                                                }
                                            }

                                            return Promise.reject(error);
                                        });
                            }
                        }

                        if (_isHttpHandlerEnabled) {
                            if (typeof _httpErrorCallback === "function") {
                                await _httpErrorCallback(error);
                            }
                            if (typeof _httpFinishCallback === "function") {
                                _httpFinishCallback();
                            }
                        }

                        return Promise.reject(error);
                    })
            );
        } else {
            return Promise.reject(
                new AsgardeoSPAException(
                    "MAIN_THREAD_CLIENT-HRA-IV02",
                    "main-thread-client",
                    "httpRequest",
                    "Request to the provided endpoint is prohibited.",
                    "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                        " attribute while initializing the SDK. The specified endpoint in this request " +
                        "cannot be found among the `resourceServerURLs`"
                )
            );
        }
    };

    const getHttpClient = (): HttpClientInstance => {
        return _httpClient;
    };

    const enableHttpHandler = (): boolean => {
        _httpClient?.enableHandler && _httpClient.enableHandler();
        _isHttpHandlerEnabled = true;

        return true;
    };

    const disableHttpHandler = (): boolean => {
        _httpClient?.disableHandler && _httpClient.disableHandler();
        _isHttpHandlerEnabled = false;

        return true;
    };

    const checkSession = async (): Promise<void> => {
        const oidcEndpoints: OIDCEndpoints = await _authenticationClient.getOIDCServiceEndpoints();
        const config = await _dataLayer.getConfigData();

        _sessionManagementHelper.initialize(
            config.clientID,
            oidcEndpoints.checkSessionIframe ?? "",
            async () => (await _authenticationClient.getBasicUserInfo()).sessionState,
            config.checkSessionInterval ?? 3,
            config.sessionRefreshInterval ?? 300,
            config.signInRedirectURL,
            async (params?: GetAuthURLConfig): Promise<string> =>  _authenticationClient.getAuthorizationURL(params)
        );
    };

    const signIn = async (
        signInConfig?: GetAuthURLConfig,
        authorizationCode?: string,
        sessionState?: string,
        state?: string
    ): Promise<BasicUserInfo> => {
        const config = await _dataLayer.getConfigData();

        const shouldStopContinue: boolean = await _sessionManagementHelper.receivePromptNoneResponse(
            async (sessionState: string | null) => {
                await _dataLayer.setSessionDataParameter(SESSION_STATE, sessionState ?? "");
                return;
            }
        );

        if (shouldStopContinue) {
            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                sub: "",
                tenantDomain: "",
                username: ""
            });
        }

        if (await _authenticationClient.isAuthenticated()) {
            _spaHelper.clearRefreshTokenTimeout();
            _spaHelper.refreshAccessTokenAutomatically();

            // Enable OIDC Sessions Management only if it is set to true in the config.
            if (config.enableOIDCSessionManagement) {
                checkSession();
            }

            return Promise.resolve(await _authenticationClient.getBasicUserInfo());
        }

        let resolvedAuthorizationCode: string;
        let resolvedSessionState: string;
        let resolvedState: string;

        if (config?.responseMode === ResponseMode.formPost && authorizationCode) {
            resolvedAuthorizationCode = authorizationCode;
            resolvedSessionState = sessionState ?? "";
            resolvedState = state ?? "";
        } else {
            resolvedAuthorizationCode = new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE) ?? "";
            resolvedSessionState = new URL(window.location.href).searchParams.get(SESSION_STATE) ?? "";
            resolvedState = new URL(window.location.href).searchParams.get(STATE) ?? "";

            SPAUtils.removeAuthorizationCode();
        }

        if (resolvedAuthorizationCode) {
            return requestAccessToken(resolvedAuthorizationCode, resolvedSessionState, resolvedState);
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
            if (config.storage === Storage.BrowserMemory && config.enablePKCE) {
                const pkceKey: string = AuthenticationUtils.extractPKCEKeyFromStateParam(resolvedState);

                SPAUtils.setPKCE(pkceKey, (await _authenticationClient.getPKCECode(resolvedState)) as string);
            }

            location.href = url;

            await SPAUtils.waitTillPageRedirect();

            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                sub: "",
                tenantDomain: "",
                username: ""
            });
        });
    };

    const signOut = async (): Promise<boolean> => {
        if (await _authenticationClient.isAuthenticated() && !_getSignOutURLFromSessionStorage) {
            location.href = await _authenticationClient.signOut();
        } else {
            location.href = SPAUtils.getSignOutURL();
            await _dataLayer.removeOIDCProviderMetaData();
            await _dataLayer.removeTemporaryData();
            await _dataLayer.removeSessionData();
        }

        _spaHelper.clearRefreshTokenTimeout();

        await SPAUtils.waitTillPageRedirect();

        return true;
    };

    const requestCustomGrant = async (config: SPACustomGrantConfig): Promise<BasicUserInfo | FetchResponse> => {
        let useDefaultEndpoint = true;
        let matches = false;
        const clientConfig = await _dataLayer.getConfigData();

        // If the config does not contains a token endpoint, default token endpoint will be used.
        if (config?.tokenEndpoint) {
            useDefaultEndpoint = false;
            for (const baseUrl of [
                ...((await _dataLayer.getConfigData())?.resourceServerURLs ?? []),
                clientConfig?.serverOrigin
            ]) {
                if (config.tokenEndpoint?.startsWith(baseUrl)) {
                    matches = true;
                    break;
                }
            }
        }
        if(config.shouldReplayAfterRefresh) {
            _dataLayer.setTemporaryDataParameter(CUSTOM_GRANT_CONFIG, JSON.stringify(config));
        }
        if (useDefaultEndpoint || matches) {
            return _authenticationClient
                .requestCustomGrant(config)
                .then(async (response: FetchResponse | TokenResponse) => {
                    if (config.preventSignOutURLUpdate) {
                        _getSignOutURLFromSessionStorage = true;
                    }

                    if (config.returnsSession) {
                        _spaHelper.refreshAccessTokenAutomatically();

                        return _authenticationClient.getBasicUserInfo();
                    } else {
                        return response as FetchResponse;
                    }
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        } else {
            return Promise.reject(
                new AsgardeoSPAException(
                    "MAIN_THREAD_CLIENT-RCG-IV01",
                    "main-thread-client",
                    "requestCustomGrant",
                    "Request to the provided endpoint is prohibited.",
                    "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                        " attribute while initializing the SDK. The specified token endpoint in this request " +
                        "cannot be found among the `resourceServerURLs`"
                )
            );
        }
    };

    const refreshAccessToken = async (): Promise<BasicUserInfo> => {
        try {
            await _authenticationClient.refreshAccessToken();
            const customGrantConfig = await getCustomGrantConfigData();
            if (customGrantConfig) {
                await requestCustomGrant(customGrantConfig);
            }
            _spaHelper.refreshAccessTokenAutomatically();

            return _authenticationClient.getBasicUserInfo();
        } catch (error) {
            return Promise.reject(error);
        }
    };

    const revokeAccessToken = (): Promise<boolean> => {
        return _authenticationClient
            .revokeAccessToken()
            .then(() => {
                _sessionManagementHelper.reset();
                _spaHelper.clearRefreshTokenTimeout();

                return Promise.resolve(true);
            })
            .catch((error) => Promise.reject(error));
    };

    const requestAccessToken = async (
        resolvedAuthorizationCode: string,
        resolvedSessionState: string,
        resolvedState: string
    ): Promise<BasicUserInfo> => {
        const config = await _dataLayer.getConfigData();

        if (config.storage === Storage.BrowserMemory && config.enablePKCE) {
            const pkce = SPAUtils.getPKCE(AuthenticationUtils.extractPKCEKeyFromStateParam(resolvedState));

            await _authenticationClient.setPKCECode(
                AuthenticationUtils.extractPKCEKeyFromStateParam(resolvedState),
                pkce);
        }

        return _authenticationClient
            .requestAccessToken(resolvedAuthorizationCode, resolvedSessionState, resolvedState)
            .then(async () => {
                // Disable this temporarily
                /* if (config.storage === Storage.BrowserMemory) {
                    SPAUtils.setSignOutURL(await _authenticationClient.getSignOutURL());
                } */
                SPAUtils.setSignOutURL(await _authenticationClient.getSignOutURL());

                _spaHelper.clearRefreshTokenTimeout();
                _spaHelper.refreshAccessTokenAutomatically();

                // Enable OIDC Sessions Management only if it is set to true in the config.
                if (config.enableOIDCSessionManagement) {
                    checkSession();
                }

                return _authenticationClient.getBasicUserInfo();
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * This method checks if there is an active user session in the server by sending a prompt none request.
     * If the user is signed in, this method sends a token request. Returns false otherwise.
     *
     * @return {Promise<BasicUserInfo|boolean} Returns a Promise that resolves with the BasicUserInfo
     * if the user is signed in or with `false` if there is no active user session in the server.
     */
    const trySignInSilently = async (): Promise<BasicUserInfo | boolean> => {
        const config = await _dataLayer.getConfigData();

        if (SPAUtils.isInitializedSilentSignIn()) {
            await _sessionManagementHelper.receivePromptNoneResponse();

            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                sub: "",
                tenantDomain: "",
                username: ""
            });
        }

        const rpIFrame = document.getElementById(RP_IFRAME) as HTMLIFrameElement;

        const promptNoneIFrame: HTMLIFrameElement = rpIFrame?.contentDocument?.getElementById(
            PROMPT_NONE_IFRAME
        ) as HTMLIFrameElement;

        try {
            const urlString: string = await _authenticationClient.getAuthorizationURL({
                prompt: "none",
                state: SILENT_SIGN_IN_STATE
            });

            // Replace form_post with query
            const urlObject = new URL(urlString);
            urlObject.searchParams.set("response_mode", "query");
            const url: string = urlObject.toString();

            if (config.storage === Storage.BrowserMemory && config.enablePKCE) {
                const state = urlObject.searchParams.get(STATE);

                SPAUtils.setPKCE(
                    AuthenticationUtils.extractPKCEKeyFromStateParam( state ?? ""),
                    (await _authenticationClient.getPKCECode(state ?? "")) as string);
            }

            promptNoneIFrame.src = url;
        } catch (error) {
            return Promise.reject(error);
        }

        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                resolve(false);
            }, 10000);

            const listenToPromptNoneIFrame = async (e: MessageEvent) => {
                const data: Message<AuthorizationInfo | null> = e.data;

                if (data?.type == CHECK_SESSION_SIGNED_OUT) {
                    window.removeEventListener("message", listenToPromptNoneIFrame);
                    clearTimeout(timer);
                    resolve(false);
                }

                if (data?.type == CHECK_SESSION_SIGNED_IN && data?.data?.code) {
                    requestAccessToken(data.data.code, data?.data?.sessionState, data?.data?.state)
                        .then((response: BasicUserInfo) => {
                            window.removeEventListener("message", listenToPromptNoneIFrame);
                            resolve(response);
                        })
                        .catch((error) => {
                            window.removeEventListener("message", listenToPromptNoneIFrame);
                            reject(error);
                        })
                        .finally(() => {
                            clearTimeout(timer);
                        });
                }
            };

            window.addEventListener("message", listenToPromptNoneIFrame);
        });
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
        const existingConfig = await _dataLayer.getConfigData();
        const isCheckSessionIframeDifferent: boolean = !(
            existingConfig &&
            existingConfig.endpoints &&
            existingConfig.endpoints.checkSessionIframe &&
            newConfig &&
            newConfig.endpoints &&
            newConfig.endpoints.checkSessionIframe &&
            existingConfig.endpoints.checkSessionIframe === newConfig.endpoints.checkSessionIframe
        );
        const config = { ...existingConfig, ...newConfig };
        await _authenticationClient.updateConfig(config);

        // Re-initiates check session if the check session endpoint is updated.
        if (config.enableOIDCSessionManagement && isCheckSessionIframeDifferent) {
            _sessionManagementHelper.reset();

            checkSession();
        }
    };

    const getCustomGrantConfigData = async (): Promise<AuthClientConfig<CustomGrantConfig> | null> => {
        const configString =  await _dataLayer.getTemporaryDataParameter(CUSTOM_GRANT_CONFIG);
        if(configString) {
            return JSON.parse(configString as string);
        } else {
            return null
        }
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
        trySignInSilently,
        updateConfig
    };
};

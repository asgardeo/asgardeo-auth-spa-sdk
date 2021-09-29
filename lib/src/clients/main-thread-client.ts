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
    ResponseMode,
    SESSION_STATE,
    Store,
    TokenResponse
} from "@asgardeo/auth-js";
import {
    CHECK_SESSION_SIGNED_IN,
    CHECK_SESSION_SIGNED_OUT,
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
    const _sessionManagementHelper = SessionManagementHelper(async () => {
        return _authenticationClient.signOut();
    });

    const _httpClient: HttpClientInstance = HttpClient.getInstance();

    const attachToken = async (request: HttpRequestConfig): Promise<void> => {
        const requestConfig = { attachToken: true, ...request };
        if (requestConfig.attachToken) {
            request.headers = {
                ...request.headers,
                Authorization: `Bearer ${ await _authenticationClient.getAccessToken() }`
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

    const setHttpRequestErrorCallback = (callback: (error: HttpError) => void): void => {
        _httpClient?.setHttpRequestErrorCallback && _httpClient.setHttpRequestErrorCallback(callback);
    };

    const httpRequest = async (requestConfig: HttpRequestConfig): Promise<HttpResponse> => {
        let matches = false;
        const config = await _dataLayer.getConfigData();

        for (const baseUrl of [ ...((await config?.resourceServerURLs) ?? []), config?.serverOrigin ]) {
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
                .catch((error: HttpError) => {
                    if (error?.response?.status === 401) {
                        return _authenticationClient
                            .refreshAccessToken()
                            .then(() => {
                                return _httpClient
                                    .request(requestConfig)
                                    .then((response) => {
                                        return Promise.resolve(response);
                                    })
                                    .catch((error) => {
                                        return Promise.reject(error);
                                    });
                            })
                            .catch((refreshError) => {
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
                            });
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

            for (const baseUrl of [ ...((await config)?.resourceServerURLs ?? []), config?.serverOrigin ]) {
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
                    .catch((error: HttpError) => {
                        if (error?.response?.status === 401) {
                            return _authenticationClient
                                .refreshAccessToken()
                                .then(() => {
                                    return (
                                        _httpClient.all &&
                                        _httpClient
                                            .all(requests)
                                            .then((response) => {
                                                return Promise.resolve(response);
                                            })
                                            .catch((error) => {
                                                return Promise.reject(error);
                                            })
                                    );
                                })
                                .catch((refreshError) => {
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
                                });
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

        return true;
    };

    const disableHttpHandler = (): boolean => {
        _httpClient?.disableHandler && _httpClient.disableHandler();

        return true;
    };

    const checkSession = async (): Promise<void> => {
        const oidcEndpoints: OIDCEndpoints = await _authenticationClient.getOIDCServiceEndpoints();
        const config = await _dataLayer.getConfigData();

        _sessionManagementHelper.initialize(
            config.clientID,
            oidcEndpoints.checkSessionIframe ?? "",
            (await _authenticationClient.getBasicUserInfo()).sessionState,
            config.checkSessionInterval ?? 3,
            config.sessionRefreshInterval ?? 300,
            config.signInRedirectURL,
            oidcEndpoints.authorizationEndpoint ?? ""
        );
    };

    const signIn = async (
        signInConfig?: GetAuthURLConfig,
        authorizationCode?: string,
        sessionState?: string
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
                tenantDomain: "",
                username: ""
            });
        }

        if (SPAUtils.wasSilentSignInCalled()) {
            SPAUtils.setIsInitializedSilentSignIn();
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

        if (config?.responseMode === ResponseMode.formPost && authorizationCode) {
            resolvedAuthorizationCode = authorizationCode;
            resolvedSessionState = sessionState ?? "";
        } else {
            resolvedAuthorizationCode = new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE) ?? "";
            resolvedSessionState = new URL(window.location.href).searchParams.get(SESSION_STATE) ?? "";
            SPAUtils.removeAuthorizationCode();
        }

        if (resolvedAuthorizationCode) {
            return requestAccessToken(resolvedAuthorizationCode, resolvedSessionState);
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
                SPAUtils.setPKCE((await _authenticationClient.getPKCECode()) as string);
            }

            location.href = url;

            await SPAUtils.waitTillPageRedirect();

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

        await SPAUtils.waitTillPageRedirect();

        return true;
    };

    const requestCustomGrant = async (config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse> => {
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

        if (useDefaultEndpoint || matches) {
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

    const requestAccessToken = async (
        resolvedAuthorizationCode: string,
        resolvedSessionState: string
    ): Promise<BasicUserInfo> => {
        const config = await _dataLayer.getConfigData();

        if (config.storage === Storage.BrowserMemory && config.enablePKCE) {
            const pkce = SPAUtils.getPKCE();

            await _authenticationClient.setPKCECode(pkce);
        }

        return _authenticationClient
            .requestAccessToken(resolvedAuthorizationCode, resolvedSessionState)
            .then(async () => {
                if (config.storage === Storage.BrowserMemory) {
                    SPAUtils.setSignOutURL(await _authenticationClient.getSignOutURL());
                }

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

        if (SPAUtils.setIsInitializedSilentSignIn()) {
            await _sessionManagementHelper.receivePromptNoneResponse();

            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                tenantDomain: "",
                username: ""
            });
        }

        if (SPAUtils.isStatePresentInURL()) {
            SPAUtils.setIsInitializedSilentSignIn();

            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
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
                SPAUtils.setPKCE((await _authenticationClient.getPKCECode()) as string);
            }

            promptNoneIFrame.src = url;
        } catch (error) {
            return Promise.reject(error);
        }

        return new Promise((resolve, reject) => {
            const listenToPromptNoneIFrame = async (e: MessageEvent) => {
                const data: Message<AuthorizationInfo | null> = e.data;
                const timer = setTimeout(() => {
                    resolve(false);
                }, 10000);

                if (data?.type == CHECK_SESSION_SIGNED_OUT) {
                    window.removeEventListener("message", listenToPromptNoneIFrame);
                    clearTimeout(timer);
                    resolve(false);
                }

                if (data?.type == CHECK_SESSION_SIGNED_IN && data?.data?.code) {
                    requestAccessToken(data.data.code, data?.data?.sessionState)
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

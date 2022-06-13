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
    AsgardeoAuthException,
    AuthClientConfig,
    AuthenticationUtils,
    BasicUserInfo,
    CryptoHelper,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    FetchResponse,
    GetAuthURLConfig,
    OIDCEndpoints,
    ResponseMode,
    SESSION_STATE,
    STATE,
    Store
} from "@asgardeo/auth-js";
import {
    DISABLE_HTTP_HANDLER,
    ENABLE_HTTP_HANDLER,
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
    REQUEST_FINISH,
    REQUEST_START,
    REQUEST_SUCCESS,
    REVOKE_ACCESS_TOKEN,
    SET_SESSION_STATE,
    SIGN_OUT,
    SILENT_SIGN_IN_STATE,
    START_AUTO_REFRESH_TOKEN,
    Storage,
    UPDATE_CONFIG
} from "../constants";
import { AuthenticationHelper, SPAHelper, SessionManagementHelper } from "../helpers";
import {
    AuthorizationInfo,
    AuthorizationResponse,
    HttpClient,
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    Message,
    ResponseMessage,
    WebWorkerClientConfig,
    WebWorkerClientInterface
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

export const WebWorkerClient = async (
    config: AuthClientConfig<WebWorkerClientConfig>,
    webWorker: new () => Worker,
    getAuthHelper: (
        authClient: AsgardeoAuthClient<WebWorkerClientConfig>,
        spaHelper: SPAHelper<WebWorkerClientConfig>
    ) => AuthenticationHelper<WebWorkerClientConfig>
): Promise<WebWorkerClientInterface> => {
    /**
     * HttpClient handlers
     */
    let httpClientHandlers: HttpClient;
    /**
     * API request time out.
     */
    const _requestTimeout: number = config?.requestTimeout ?? 60000;
    let _isHttpHandlerEnabled: boolean = true;
    let _getSignOutURLFromSessionStorage: boolean = false;
    
    const _store: Store = initiateStore(config.storage);
    const _cryptoUtils: SPACryptoUtils = new SPACryptoUtils();
    const _authenticationClient = new AsgardeoAuthClient<WebWorkerClientConfig>(_store, _cryptoUtils);
    await _authenticationClient.initialize(config);
    const _spaHelper = new SPAHelper<WebWorkerClientConfig>(_authenticationClient);
    
    const _sessionManagementHelper = await SessionManagementHelper(
        async () => {
            const message: Message<string> = {
                type: SIGN_OUT
            };

            try {
                const signOutURL = await communicate<string, string>(message);

                return signOutURL;
            } catch {
                return SPAUtils.getSignOutURL();
            }
        },
        config.storage,
        (sessionState: string) => setSessionState(sessionState)
    );

    const _authenticationHelper: AuthenticationHelper<WebWorkerClientConfig> = 
        getAuthHelper(_authenticationClient, _spaHelper);

    const worker: Worker = new webWorker();

    const communicate = <T, R>(message: Message<T>): Promise<R> => {
        const channel = new MessageChannel();

        worker.postMessage(message, [ channel.port2 ]);

        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(
                    new AsgardeoAuthException(
                        "SPA-WEB_WORKER_CLIENT-COM-TO01",
                        "Operation timed out.",
                        "No response was received from the web worker for " +
                        _requestTimeout / 1000 +
                        " since dispatching the request"
                    )
                );
            }, _requestTimeout);

            return (channel.port1.onmessage = ({ data }: { data: ResponseMessage<string>; }) => {
                clearTimeout(timer);

                if (data?.success) {
                    const responseData = data?.data ? JSON.parse(data?.data) : null;
                    if (data?.blob) {
                        responseData.data = data?.blob;
                    }

                    resolve(responseData);
                } else {
                    reject(data.error ? JSON.parse(data.error) : null);
                }
            });
        });
    };

    /**
     * Allows using custom grant types.
     *
     * @param {CustomGrantRequestParams} requestParams Request Parameters.
     *
     * @returns {Promise<HttpResponse|boolean>} A promise that resolves with a boolean value or the request
     * response if the the `returnResponse` attribute in the `requestParams` object is set to `true`.
     */
    const requestCustomGrant = (requestParams: SPACustomGrantConfig): Promise<FetchResponse | BasicUserInfo> => {
        const message: Message<CustomGrantConfig> = {
            data: requestParams,
            type: REQUEST_CUSTOM_GRANT
        };

        return communicate<CustomGrantConfig, FetchResponse | BasicUserInfo>(message)
            .then((response) => {
                if (requestParams.preventSignOutURLUpdate) {
                    _getSignOutURLFromSessionStorage = true;
                }

                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     *
     * Send the API request to the web worker and returns the response.
     *
     * @param {HttpRequestConfig} config The Http Request Config object
     *
     * @returns {Promise<HttpResponse>} A promise that resolves with the response data.
     */
    const httpRequest = <T = any>(config: HttpRequestConfig): Promise<HttpResponse<T>> => {
        const message: Message<HttpRequestConfig> = {
            data: config,
            type: HTTP_REQUEST
        };

        return communicate<HttpRequestConfig, HttpResponse<T>>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch(async (error) => {
                if (_isHttpHandlerEnabled) {
                    if (typeof httpClientHandlers.requestErrorCallback === "function") {
                        await httpClientHandlers.requestErrorCallback(error);
                    }
                    if (typeof httpClientHandlers.requestFinishCallback === "function") {
                        httpClientHandlers.requestFinishCallback();
                    }
                }

                return Promise.reject(error);
            });
    };

    /**
     *
     * Send multiple API requests to the web worker and returns the response.
     * Similar `axios.spread` in functionality.
     *
     * @param {HttpRequestConfig[]} configs - The Http Request Config object
     *
     * @returns {Promise<HttpResponse<T>[]>} A promise that resolves with the response data.
     */
    const httpRequestAll = <T = any>(configs: HttpRequestConfig[]): Promise<HttpResponse<T>[]> => {
        const message: Message<HttpRequestConfig[]> = {
            data: configs,
            type: HTTP_REQUEST_ALL
        };

        return communicate<HttpRequestConfig[], HttpResponse<T>[]>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch(async (error) => {
                if (_isHttpHandlerEnabled) {
                    if (typeof httpClientHandlers.requestErrorCallback === "function") {
                        await httpClientHandlers.requestErrorCallback(error);
                    }
                    if (typeof httpClientHandlers.requestFinishCallback === "function") {
                        httpClientHandlers.requestFinishCallback();
                    }
                }

                return Promise.reject(error);
            });
    };

    const enableHttpHandler = (): Promise<boolean> => {
        const message: Message<null> = {
            type: ENABLE_HTTP_HANDLER
        };
        return communicate<null, null>(message)
            .then(() => {
                _isHttpHandlerEnabled = true;

                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const disableHttpHandler = (): Promise<boolean> => {
        const message: Message<null> = {
            type: DISABLE_HTTP_HANDLER
        };
        return communicate<null, null>(message)
            .then(() => {
                _isHttpHandlerEnabled = false;

                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * Initializes the object with authentication parameters.
     *
     * @param {ConfigInterface} config The configuration object.
     *
     * @returns {Promise<boolean>} Promise that resolves when initialization is successful.
     *
     */
    const initialize = (): Promise<boolean> => {
        if (!httpClientHandlers) {
            httpClientHandlers = {
                requestErrorCallback: () => Promise.resolve(),
                requestFinishCallback: () => null,
                requestStartCallback: () => null,
                requestSuccessCallback: () => null
            };
        }

        worker.onmessage = ({ data }) => {
            switch (data.type) {
                case REQUEST_FINISH:
                    httpClientHandlers?.requestFinishCallback && httpClientHandlers?.requestFinishCallback();
                    break;
                case REQUEST_START:
                    httpClientHandlers?.requestStartCallback && httpClientHandlers?.requestStartCallback();
                    break;
                case REQUEST_SUCCESS:
                    httpClientHandlers?.requestSuccessCallback &&
                        httpClientHandlers?.requestSuccessCallback(data.data ? JSON.parse(data.data) : null);
                    break;
            }
        };

        const message: Message<AuthClientConfig<WebWorkerClientConfig>> = {
            data: config,
            type: INIT
        };

        return communicate<AuthClientConfig<WebWorkerClientConfig>, null>(message)
            .then(() => {
                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const setSessionState = (sessionState: string | null): Promise<void> => {
        const message: Message<string | null> = {
            data: sessionState,
            type: SET_SESSION_STATE
        };

        return communicate<string | null, void>(message);
    };

    const startAutoRefreshToken = (): Promise<void> => {
        const message: Message<null> = {
            type: START_AUTO_REFRESH_TOKEN
        };

        return communicate<null, void>(message);
    };

    const checkSession = async (): Promise<void> => {
        const oidcEndpoints: OIDCEndpoints = await getOIDCServiceEndpoints();
        const config: AuthClientConfig<WebWorkerClientConfig> = await getConfigData();

        _authenticationHelper.initializeSessionManger(
            config,
            oidcEndpoints,
            async () => (await getBasicUserInfo()).sessionState,
            async (params?: GetAuthURLConfig): Promise<string> => (await getAuthorizationURL(params)).authorizationURL,
            _sessionManagementHelper
        );
    };

    const constructSilentSignInUrl = async (): Promise<string> => {
        const config: AuthClientConfig<WebWorkerClientConfig> = await getConfigData();
        const message: Message<GetAuthURLConfig> = {
            data: {
                prompt: "none",
                state: SILENT_SIGN_IN_STATE
            },
            type: GET_AUTH_URL
        };

        const response: AuthorizationResponse = await communicate<GetAuthURLConfig, AuthorizationResponse>(message);

        const pkceKey: string = AuthenticationUtils.extractPKCEKeyFromStateParam(
            new URL(response.authorizationURL).searchParams.get(STATE) ?? ""
        );

        response.pkce && config.enablePKCE && SPAUtils.setPKCE(pkceKey, response.pkce);

        const urlString: string = response.authorizationURL;

        // Replace form_post with query
        const urlObject = new URL(urlString);
        urlObject.searchParams.set("response_mode", "query");
        const url: string = urlObject.toString();

        return url;
    }

    /**
     * This method checks if there is an active user session in the server by sending a prompt none request.
     * If the user is signed in, this method sends a token request. Returns false otherwise.
     *
     * @return {Promise<BasicUserInfo|boolean} Returns a Promise that resolves with the BasicUserInfo
     * if the user is signed in or with `false` if there is no active user session in the server.
     */
    const trySignInSilently = async (): Promise<BasicUserInfo | boolean> => {
        return await _authenticationHelper.trySignInSilently(
            constructSilentSignInUrl,
            requestAccessToken,
            _sessionManagementHelper
        );
    };

    /**
     * Generates an authorization URL.
     *
     * @param {GetAuthURLConfig} params Authorization URL params.
     * @returns {Promise<string>} Authorization URL.
     */
    const getAuthorizationURL = async (params?: GetAuthURLConfig): Promise<AuthorizationResponse> => {
        const config: AuthClientConfig<WebWorkerClientConfig> = await getConfigData();

        const message: Message<GetAuthURLConfig> = {
            data: params,
            type: GET_AUTH_URL
        };

        return communicate<GetAuthURLConfig, AuthorizationResponse>(message).then(
            async (response: AuthorizationResponse) => {
                if (response.pkce && config.enablePKCE) {
                    const pkceKey: string = AuthenticationUtils.extractPKCEKeyFromStateParam(
                        new URL(response.authorizationURL).searchParams.get(STATE) ?? ""
                    );

                    SPAUtils.setPKCE(pkceKey, response.pkce);
                }

                return Promise.resolve(response);
            }
        );
    };

    const requestAccessToken = async (
        resolvedAuthorizationCode: string,
        resolvedSessionState: string,
        resolvedState: string
    ): Promise<BasicUserInfo> => {
        const config: AuthClientConfig<WebWorkerClientConfig> = await getConfigData();
        const pkceKey: string = AuthenticationUtils.extractPKCEKeyFromStateParam(resolvedState);

        const message: Message<AuthorizationInfo> = {
            data: {
                code: resolvedAuthorizationCode,
                pkce: config.enablePKCE ? SPAUtils.getPKCE(pkceKey) : undefined,
                sessionState: resolvedSessionState,
                state: resolvedState
            },
            type: REQUEST_ACCESS_TOKEN
        };

        config.enablePKCE && SPAUtils.removePKCE(pkceKey);

        return communicate<AuthorizationInfo, BasicUserInfo>(message)
            .then((response) => {
                const message: Message<null> = {
                    type: GET_SIGN_OUT_URL
                };

                return communicate<null, string>(message)
                    .then((url: string) => {
                        SPAUtils.setSignOutURL(url);

                        // Enable OIDC Sessions Management only if it is set to true in the config.
                        if (config.enableOIDCSessionManagement) {
                            checkSession();
                        }

                        startAutoRefreshToken();

                        return Promise.resolve(response);
                    })
                    .catch((error) => {
                        return Promise.reject(error);
                    });
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const shouldStopAuthn = async (): Promise<boolean> => {
        return await _sessionManagementHelper.receivePromptNoneResponse(
            async (sessionState: string | null) => {
                return setSessionState(sessionState);
            }
        );
    }

    const tryRetrievingUserInfo = async (): Promise<BasicUserInfo | undefined> => {
        if (await isAuthenticated()) {
            await startAutoRefreshToken();

            // Enable OIDC Sessions Management only if it is set to true in the config.
            if (config.enableOIDCSessionManagement) {
                checkSession();
            }

            return getBasicUserInfo();
        }
    }
    
    /**
     * Initiates the authentication flow.
     *
     * @returns {Promise<UserInfo>} A promise that resolves when authentication is successful.
     */
    const signIn = async (
        params?: GetAuthURLConfig,
        authorizationCode?: string,
        sessionState?: string,
        state?: string
    ): Promise<BasicUserInfo> => {

        const basicUserInfo =  await _authenticationHelper.handleSignIn(
            shouldStopAuthn,
            checkSession,
            tryRetrievingUserInfo
        );

        if(basicUserInfo) {
            return basicUserInfo;
        } else {
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

            if (resolvedAuthorizationCode && resolvedState) {
                return requestAccessToken(resolvedAuthorizationCode, resolvedSessionState, resolvedState);
            }
            
            return getAuthorizationURL(params)
                .then(async (response: AuthorizationResponse) => {
                    location.href = response.authorizationURL;

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
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }
    };

    /**
     * Initiates the sign out flow.
     *
     * @returns {Promise<boolean>} A promise that resolves when sign out is completed.
     */
    const signOut = (): Promise<boolean> => {
        return isAuthenticated()
            .then(async (response: boolean) => {
                if (response && !_getSignOutURLFromSessionStorage) {
                    const message: Message<null> = {
                        type: SIGN_OUT
                    };

                    return communicate<null, string>(message)
                        .then(async (response) => {
                            window.location.href = response;

                            await SPAUtils.waitTillPageRedirect();

                            return Promise.resolve(true);
                        })
                        .catch((error) => {
                            return Promise.reject(error);
                        });
                } else {
                    window.location.href = SPAUtils.getSignOutURL();

                    await SPAUtils.waitTillPageRedirect();

                    return Promise.resolve(true);
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * Revokes token.
     *
     * @returns {Promise<boolean>} A promise that resolves when revoking is completed.
     */
    const revokeAccessToken = (): Promise<boolean> => {
        const message: Message<null> = {
            type: REVOKE_ACCESS_TOKEN
        };

        return communicate<null, boolean>(message)
            .then((response) => {
                _sessionManagementHelper.reset();
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getOIDCServiceEndpoints = (): Promise<OIDCEndpoints> => {
        const message: Message<null> = {
            type: GET_OIDC_SERVICE_ENDPOINTS
        };

        return communicate<null, OIDCEndpoints>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getConfigData = (): Promise<AuthClientConfig<WebWorkerClientConfig>> => {
        const message: Message<null> = {
            type: GET_CONFIG_DATA
        };

        return communicate<null, AuthClientConfig<WebWorkerClientConfig>>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getBasicUserInfo = (): Promise<BasicUserInfo> => {
        const message: Message<null> = {
            type: GET_BASIC_USER_INFO
        };

        return communicate<null, BasicUserInfo>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getDecodedIDToken = (): Promise<DecodedIDTokenPayload> => {
        const message: Message<null> = {
            type: GET_DECODED_ID_TOKEN
        };

        return communicate<null, DecodedIDTokenPayload>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getDecodedIDPIDToken = (): Promise<DecodedIDTokenPayload> => {
        const message: Message<null> = {
            type: GET_DECODED_IDP_ID_TOKEN
        };

        return communicate<null, DecodedIDTokenPayload>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getCryptoHelper = (): Promise<CryptoHelper> => {
        const message: Message<null> = {
            type: GET_CRYPTO_HELPER
        };

        return communicate<null, CryptoHelper>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getIDToken = (): Promise<string> => {
        const message: Message<null> = {
            type: GET_ID_TOKEN
        };

        return communicate<null, string>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const isAuthenticated = (): Promise<boolean> => {
        const message: Message<null> = {
            type: IS_AUTHENTICATED
        };

        return communicate<null, boolean>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const refreshAccessToken = (): Promise<BasicUserInfo> => {
        const message: Message<null> = {
            type: REFRESH_ACCESS_TOKEN
        };

        return communicate<null, BasicUserInfo>(message);
    };

    const setHttpRequestSuccessCallback = (callback: (response: HttpResponse) => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestSuccessCallback = callback;
        }
    };

    const setHttpRequestErrorCallback = (callback: (response: HttpError) => void | Promise<void>): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestErrorCallback = callback;
        }
    };

    const setHttpRequestStartCallback = (callback: () => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestStartCallback = callback;
        }
    };

    const setHttpRequestFinishCallback = (callback: () => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestFinishCallback = callback;
        }
    };

    const updateConfig = async (newConfig: Partial<AuthClientConfig<WebWorkerClientConfig>>): Promise<void> => {
        const existingConfig = await getConfigData();
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

        const message: Message<Partial<AuthClientConfig<WebWorkerClientConfig>>> = {
            data: config,
            type: UPDATE_CONFIG
        };

        await communicate<Partial<AuthClientConfig<WebWorkerClientConfig>>, void>(message);

        // Re-initiates check session if the check session endpoint is updated.
        if (config.enableOIDCSessionManagement && isCheckSessionIframeDifferent) {
            _sessionManagementHelper.reset();

            checkSession();
        }
    };

    return {
        disableHttpHandler,
        enableHttpHandler,
        getBasicUserInfo,
        getCryptoHelper,
        getDecodedIDPIDToken,
        getDecodedIDToken,
        getIDToken,
        getOIDCServiceEndpoints,
        httpRequest,
        httpRequestAll,
        initialize,
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

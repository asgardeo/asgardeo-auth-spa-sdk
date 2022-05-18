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
    CHECK_SESSION_SIGNED_IN,
    CHECK_SESSION_SIGNED_OUT,
    ERROR,
    ERROR_DESCRIPTION,
    PROMPT_NONE_IFRAME,
    RP_IFRAME,
    SILENT_SIGN_IN_STATE,
    Storage
} from "../constants";
import { AuthenticationHelper, SPAHelper, SessionManagementHelper } from "../helpers";
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
    const _authenticationHelper = new AuthenticationHelper<MainThreadClientConfig>(_authenticationClient);
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

    _httpClient?.init && (await _httpClient.init(true, _authenticationHelper.attachToken));

    const setHttpRequestStartCallback = (callback: () => void): void => {
        _authenticationHelper.setHttpRequestStartCallback(_httpClient, callback);
    };

    const setHttpRequestSuccessCallback = (callback: (response: HttpResponse) => void): void => {
        _authenticationHelper.setHttpRequestSuccessCallback(_httpClient, callback);
    };

    const setHttpRequestFinishCallback = (callback: () => void): void => {
        _authenticationHelper.setHttpRequestFinishCallback(_httpClient, callback);
        _httpFinishCallback = callback;
    };

    const setHttpRequestErrorCallback = (callback: (error: HttpError) => void | Promise<void>): void => {
        _httpErrorCallback = callback;
    };

    const httpRequest = async (requestConfig: HttpRequestConfig): Promise<HttpResponse> => {
        return await _authenticationHelper.httpRequest(
            _httpClient, 
            requestConfig, 
            _spaHelper, 
            _isHttpHandlerEnabled,
            _httpErrorCallback,
            _httpFinishCallback
        );
    };

    const httpRequestAll = async (requestConfigs: HttpRequestConfig[]): Promise<HttpResponse[] | undefined> => {
        return await _authenticationHelper.httpRequestAll(
            requestConfigs,
            _httpClient,
            _isHttpHandlerEnabled,
            _httpErrorCallback,
            _httpFinishCallback
        );
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
            async (params?: GetAuthURLConfig): Promise<string> => _authenticationClient.getAuthorizationURL(params)
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

        if (resolvedAuthorizationCode && resolvedState) {
            return requestAccessToken(resolvedAuthorizationCode, resolvedSessionState, resolvedState);
        }

        const error = new URL(window.location.href).searchParams.get(ERROR);
        const errorDescription = new URL(window.location.href).searchParams.get(ERROR_DESCRIPTION);

        if (error) {
            const url = new URL(window.location.href);
            url.searchParams.delete(ERROR);
            url.searchParams.delete(ERROR_DESCRIPTION);

            history.pushState(null, document.title, url.toString());

            throw new AsgardeoAuthException("SPA-MAIN_THREAD_CLIENT-SI-SE01", error, errorDescription ?? "");
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
        if ((await _authenticationClient.isAuthenticated()) && !_getSignOutURLFromSessionStorage) {
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

    const enableRetrievingSignOutURLFromSession = (config: SPACustomGrantConfig) => {
        if (config.preventSignOutURLUpdate) {
            _getSignOutURLFromSessionStorage = true;
        }
    }

    const requestCustomGrant = async (config: SPACustomGrantConfig): 
        Promise<BasicUserInfo | FetchResponse> => {
            return await _authenticationHelper.requestCustomGrant(
                    config, 
                    _spaHelper, 
                    enableRetrievingSignOutURLFromSession
                );
    };

    const refreshAccessToken = async (): Promise<BasicUserInfo> => {
        try {
            return await _authenticationHelper.refreshAccessToken(
                _spaHelper, 
                enableRetrievingSignOutURLFromSession
            );
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
                pkce
            );
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
                    AuthenticationUtils.extractPKCEKeyFromStateParam(state ?? ""),
                    (await _authenticationClient.getPKCECode(state ?? "")) as string
                );
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

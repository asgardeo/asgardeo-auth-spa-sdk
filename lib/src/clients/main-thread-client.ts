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
    CryptoHelper,
    DataLayer,
    DecodedIDTokenPayload,
    FetchResponse,
    GetAuthURLConfig,
    OIDCEndpoints,
    ResponseMode,
    SESSION_STATE,
    STATE,
    SessionData,
    Store
} from "@asgardeo/auth-js";
import {
    SILENT_SIGN_IN_STATE,
    Storage
} from "../constants";
import { AuthenticationHelper, SPAHelper, SessionManagementHelper } from "../helpers";
import { HttpClient, HttpClientInstance } from "../http-client";
import {
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    MainThreadClientConfig,
    MainThreadClientInterface
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
    instanceID: number,
    config: AuthClientConfig<MainThreadClientConfig>,
    getAuthHelper: (
        authClient: AsgardeoAuthClient<MainThreadClientConfig>,
        spaHelper: SPAHelper<MainThreadClientConfig>
    ) => AuthenticationHelper<MainThreadClientConfig>
): Promise<MainThreadClientInterface> => {
    const _store: Store = initiateStore(config.storage);
    const _cryptoUtils: SPACryptoUtils = new SPACryptoUtils();
    const _authenticationClient = new AsgardeoAuthClient<MainThreadClientConfig>();
    await _authenticationClient.initialize(config, _store, _cryptoUtils, instanceID);

    const _spaHelper = new SPAHelper<MainThreadClientConfig>(_authenticationClient);
    const _dataLayer = _authenticationClient.getDataLayer();
    const _sessionManagementHelper = await SessionManagementHelper(
        async () => {
            return _authenticationClient.getSignOutURL();
        },
        config.storage ?? Storage.SessionStorage,
        (sessionState: string) => _dataLayer.setSessionDataParameter(SESSION_STATE as keyof SessionData, 
            sessionState ?? "")
    );

    const _authenticationHelper = getAuthHelper(_authenticationClient, _spaHelper);

    let _getSignOutURLFromSessionStorage: boolean = false;

    const _httpClient: HttpClientInstance = HttpClient.getInstance();
    let _isHttpHandlerEnabled: boolean = true;
    let _httpErrorCallback: (error: HttpError) => void | Promise<void>;
    let _httpFinishCallback: () => void;

    const attachToken = async (request: HttpRequestConfig): Promise<void> => {
        await _authenticationHelper.attachTokenToRequestConfig(request);
    }

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

    const setHttpRequestErrorCallback = (callback: (error: HttpError) => void | Promise<void>): void => {
        _httpErrorCallback = callback;
    };

    const httpRequest = async (requestConfig: HttpRequestConfig): Promise<HttpResponse> => {
        return await _authenticationHelper.httpRequest(
            _httpClient,
            requestConfig,
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
        _authenticationHelper.enableHttpHandler(_httpClient);
        _isHttpHandlerEnabled = true;

        return true;
    };

    const disableHttpHandler = (): boolean => {
        _authenticationHelper.disableHttpHandler(_httpClient);
        _isHttpHandlerEnabled = false;

        return true;
    };

    const checkSession = async (): Promise<void> => {
        const oidcEndpoints: OIDCEndpoints = await _authenticationClient.getOIDCServiceEndpoints();
        const config = await _dataLayer.getConfigData();

        _authenticationHelper.initializeSessionManger(
            config,
            oidcEndpoints,
            async () => (await _authenticationClient.getBasicUserInfo()).sessionState,
            async (params?: GetAuthURLConfig): Promise<string> => _authenticationClient.getAuthorizationURL(params),
            _sessionManagementHelper
        );
    };

    const shouldStopAuthn = async (): Promise<boolean> => {
        return await _sessionManagementHelper.receivePromptNoneResponse(
            async (sessionState: string | null) => {
                await _dataLayer.setSessionDataParameter(SESSION_STATE as keyof SessionData, sessionState ?? "");
                return;
            }
        );
    }

    const signIn = async (
        signInConfig?: GetAuthURLConfig,
        authorizationCode?: string,
        sessionState?: string,
        state?: string
    ): Promise<BasicUserInfo> => {

        const basicUserInfo =  await _authenticationHelper.handleSignIn(
            shouldStopAuthn,
            checkSession
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
        }
    };

    const signOut = async (): Promise<boolean> => {
        if ((await _authenticationClient.isAuthenticated()) && !_getSignOutURLFromSessionStorage) {
            location.href = await _authenticationClient.getSignOutURL();
        } else {
            location.href = SPAUtils.getSignOutURL(config.clientID, instanceID);
        }

        _spaHelper.clearRefreshTokenTimeout();

        await _dataLayer.removeOIDCProviderMetaData();
        await _dataLayer.removeTemporaryData();
        await _dataLayer.removeSessionData();

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
                    enableRetrievingSignOutURLFromSession
                );
    };

    const refreshAccessToken = async (): Promise<BasicUserInfo> => {
        try {
            return await _authenticationHelper.refreshAccessToken(
                enableRetrievingSignOutURLFromSession
            );
        } catch (error) {
            return Promise.reject(error);
        }
    };

    const revokeAccessToken = async (): Promise<boolean> => {
        const timer: number = await _spaHelper.getRefreshTimeoutTimer();

        return _authenticationClient
            .revokeAccessToken()
            .then(() => {
                _sessionManagementHelper.reset();
                _spaHelper.clearRefreshTokenTimeout(timer);

                return Promise.resolve(true);
            })
            .catch((error) => Promise.reject(error));
    };

    const requestAccessToken = async (
        resolvedAuthorizationCode: string,
        resolvedSessionState: string,
        resolvedState: string
    ): Promise<BasicUserInfo> => {
        return await _authenticationHelper.requestAccessToken(
            resolvedAuthorizationCode,
            resolvedSessionState,
            checkSession,
            undefined,
            resolvedState
        );
    };

    const constructSilentSignInUrl = async (): Promise<string> => {
        const config = await _dataLayer.getConfigData();
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

    const getBasicUserInfo = async (): Promise<BasicUserInfo> => {
        return _authenticationHelper.getBasicUserInfo();
    };

    const getDecodedIDToken = async (): Promise<DecodedIDTokenPayload> => {
        return _authenticationHelper.getDecodedIDToken();
    };

    const getCryptoHelper = async (): Promise<CryptoHelper> => {
        return _authenticationHelper.getCryptoHelper();
    };

    const getIDToken = async (): Promise<string> => {
        return _authenticationHelper.getIDToken();
    };

    const getOIDCServiceEndpoints = async (): Promise<OIDCEndpoints> => {
        return _authenticationHelper.getOIDCServiceEndpoints();
    };

    const getAccessToken = async (): Promise<string> => {
        return _authenticationHelper.getAccessToken();
    };

    const getDataLayer = async (): Promise<DataLayer<MainThreadClientConfig>> => {
        return _authenticationHelper.getDataLayer();
    };

    const isAuthenticated = async (): Promise<boolean> => {
        return _authenticationHelper.isAuthenticated();
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
        getCryptoHelper,
        getDataLayer,
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

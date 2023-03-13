/**
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
    AsgardeoAuthException, 
    AuthClientConfig, 
    AuthenticationUtils, 
    BasicUserInfo, 
    CryptoHelper, 
    CustomGrantConfig, 
    DataLayer, 
    DecodedIDTokenPayload, 
    FetchResponse, 
    GetAuthURLConfig, 
    OIDCEndpoints,
    TokenResponse
} from "@asgardeo/auth-js";
import { SPAHelper } from "./spa-helper";
import { HttpRequestInterface, Message, SPAUtils, SessionManagementHelperInterface } from "..";
import { 
    ACCESS_TOKEN_INVALID, 
    CHECK_SESSION_SIGNED_IN, 
    CHECK_SESSION_SIGNED_OUT, 
    CUSTOM_GRANT_CONFIG,
    ERROR,
    ERROR_DESCRIPTION,
    PROMPT_NONE_IFRAME,
    RP_IFRAME,
    Storage  
} from "../constants";
import {
    AuthorizationInfo,
    HttpClientInstance,
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    MainThreadClientConfig,
    WebWorkerClientConfig
} from "../models";
import { SPACustomGrantConfig } from "../models/request-custom-grant";

export class AuthenticationHelper<
  T extends MainThreadClientConfig | WebWorkerClientConfig
> {
    protected _authenticationClient: AsgardeoAuthClient<T>;
    protected _dataLayer: DataLayer<T>;
    protected _spaHelper: SPAHelper<T>;
    protected _isTokenRefreshing: boolean;

    public constructor(
        authClient: AsgardeoAuthClient<T>,
        spaHelper: SPAHelper<T>
      ) {
        this._authenticationClient = authClient;
        this._dataLayer = this._authenticationClient.getDataLayer();
        this._spaHelper = spaHelper;
        this._isTokenRefreshing = false;
    }

    public enableHttpHandler(httpClient: HttpClientInstance): void {
        httpClient?.enableHandler && httpClient.enableHandler();
    }

    public disableHttpHandler (httpClient: HttpClientInstance): void {
        httpClient?.disableHandler && httpClient.disableHandler();
    }

    public initializeSessionManger(
        config: AuthClientConfig<T>,
        oidcEndpoints: OIDCEndpoints,
        getSessionState: () => Promise<string>,
        getAuthzURL: (params?: GetAuthURLConfig) => Promise<string>,
        sessionManagementHelper: SessionManagementHelperInterface
    ): void {
        sessionManagementHelper.initialize(
            config.clientID,
            oidcEndpoints.checkSessionIframe ?? "",
            getSessionState,
            config.checkSessionInterval ?? 3,
            config.sessionRefreshInterval ?? 300,
            config.signInRedirectURL,
            getAuthzURL
        );
    }

    public async requestCustomGrant(
        config: SPACustomGrantConfig,
        enableRetrievingSignOutURLFromSession?: (config: SPACustomGrantConfig) => void
    ): Promise<BasicUserInfo | FetchResponse> {
        let useDefaultEndpoint = true;
        let matches = false;
    
        // If the config does not contains a token endpoint, default token endpoint will be used.
        if (config?.tokenEndpoint) {
            useDefaultEndpoint = false;
    
            for (const baseUrl of [
                ...((await this._dataLayer.getConfigData())?.resourceServerURLs ?? []),
                (config as any).baseUrl
            ]) {
                if (baseUrl && config.tokenEndpoint?.startsWith(baseUrl)) {
                    matches = true;
                    break;
                }
            }
        }
        if (config.shouldReplayAfterRefresh) {
            this._dataLayer.setTemporaryDataParameter(
                CUSTOM_GRANT_CONFIG,
                JSON.stringify(config)
            );
        }
        if (useDefaultEndpoint || matches) {
            return this._authenticationClient
                .requestCustomGrant(config)
                    .then(async (response: FetchResponse | TokenResponse) => {
                        if (enableRetrievingSignOutURLFromSession && 
                            typeof enableRetrievingSignOutURLFromSession === "function") {
                            enableRetrievingSignOutURLFromSession(config);
                        }
                
                        if (config.returnsSession) {
                            this._spaHelper.refreshAccessTokenAutomatically(this);
                
                            return this._authenticationClient.getBasicUserInfo();
                        } else {
                            return response as FetchResponse;
                        }
                    })
                    .catch((error) => {
                        return Promise.reject(error);
                    });
        } else {
          return Promise.reject(
            new AsgardeoAuthException(
              "SPA-MAIN_THREAD_CLIENT-RCG-IV01",
              "Request to the provided endpoint is prohibited.",
              "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                " attribute while initializing the SDK. The specified token endpoint in this request " +
                "cannot be found among the `resourceServerURLs`"
            )
          );
        }
    }

    public async getCustomGrantConfigData(): Promise<AuthClientConfig<CustomGrantConfig> | null> {
        const configString = await this._dataLayer.getTemporaryDataParameter(
            CUSTOM_GRANT_CONFIG
        );

        if (configString) {
            return JSON.parse(configString as string);
        } else {
            return null;
        }
    }

    public async refreshAccessToken(
        enableRetrievingSignOutURLFromSession?: (config: SPACustomGrantConfig) => void
    ): Promise<BasicUserInfo> {
        try {
            await this._authenticationClient.refreshAccessToken();
            const customGrantConfig = await this.getCustomGrantConfigData();
            if (customGrantConfig) {
                await this.requestCustomGrant(
                        customGrantConfig,
                        enableRetrievingSignOutURLFromSession
                    );
            }
            this._spaHelper.refreshAccessTokenAutomatically(this);

            return this._authenticationClient.getBasicUserInfo();
        } catch (error) {
            return Promise.reject(error);
        }
    }

    protected async retryFailedRequests (failedRequest: HttpRequestInterface): Promise<HttpResponse> {
        const httpClient = failedRequest.httpClient;
        const requestConfig = failedRequest.requestConfig;
        const isHttpHandlerEnabled = failedRequest.isHttpHandlerEnabled;
        const httpErrorCallback = failedRequest.httpErrorCallback;
        const httpFinishCallback = failedRequest.httpFinishCallback;

        // Wait until the token is refreshed.
        await SPAUtils.until(() => !this._isTokenRefreshing);

        try {
            const httpResponse = await httpClient.request(requestConfig);

            return Promise.resolve(httpResponse);
        } catch (error: any) {
            if (isHttpHandlerEnabled) {
                if (typeof httpErrorCallback === "function") {
                    await httpErrorCallback(error);
                }
                if (typeof httpFinishCallback === "function") {
                    httpFinishCallback();
                }
            }

            return Promise.reject(error);
        }
    }

    public async httpRequest(
        httpClient: HttpClientInstance,
        requestConfig: HttpRequestConfig,
        isHttpHandlerEnabled?: boolean,
        httpErrorCallback?: (error: HttpError) => void | Promise<void>,
        httpFinishCallback?: () => void,
        enableRetrievingSignOutURLFromSession?: (config: SPACustomGrantConfig) => void
    ): Promise<HttpResponse> {
        let matches = false;
        const config = await this._dataLayer.getConfigData();

        for (const baseUrl of [
            ...((await config?.resourceServerURLs) ?? []),
            (config as any).baseUrl
        ]) {
            if (baseUrl && requestConfig?.url?.startsWith(baseUrl)) {
                matches = true;

                break;
            }
        }

        if (matches) {
            return httpClient
                .request(requestConfig)
                .then((response: HttpResponse) => {
                    return Promise.resolve(response);
                })
                .catch(async (error: HttpError) => {
                    if (error?.response?.status === 401 || !error?.response) {
                        if (this._isTokenRefreshing) {
                            return this.retryFailedRequests({
                                enableRetrievingSignOutURLFromSession,
                                httpClient,
                                httpErrorCallback,
                                httpFinishCallback,
                                isHttpHandlerEnabled,
                                requestConfig
                            });
                        }
                        this._isTokenRefreshing = true;
                        // Try to refresh the token
                        let refreshAccessTokenResponse: BasicUserInfo;
                        try {
                            refreshAccessTokenResponse = await this.refreshAccessToken(
                                enableRetrievingSignOutURLFromSession
                            );
                            this._isTokenRefreshing = false;
                        } catch (refreshError: any) {
                            this._isTokenRefreshing = false;
                            if (isHttpHandlerEnabled) {
                                if (typeof httpErrorCallback === "function") {
                                    await httpErrorCallback({ 
                                        ...error, 
                                        code: ACCESS_TOKEN_INVALID 
                                    });
                                }
                                if (typeof httpFinishCallback === "function") {
                                    httpFinishCallback();
                                }
                            }
                            
                            throw new AsgardeoAuthException(
                                "SPA-AUTH_HELPER-HR-SE01",
                                refreshError?.name ?? "Refresh token request failed.",
                                refreshError?.message ??
                                    "An error occurred while trying to refresh the " +
                                    "access token following a 401 response from the server."
                            );
                        }

                        // Retry the request after refreshing the token
                        if (refreshAccessTokenResponse) {
                            try {
                                const httpResponse = await httpClient.request(requestConfig);
                                return Promise.resolve(httpResponse);
                            } catch (error: any) {
                                if (isHttpHandlerEnabled) {
                                    if (typeof httpErrorCallback === "function") {
                                        await httpErrorCallback(error);
                                    }
                                    if (typeof httpFinishCallback === "function") {
                                        httpFinishCallback();
                                    }
                                }
                                return Promise.reject(error);
                            }
                        }
                    }

                    if (isHttpHandlerEnabled) {
                        if (typeof httpErrorCallback === "function") {
                            await httpErrorCallback(error);
                        }
                        if (typeof httpFinishCallback === "function") {
                            httpFinishCallback();
                        }
                    }

                    return Promise.reject(error);
                });
        } else {
            return Promise.reject(
                new AsgardeoAuthException(
                    "SPA-AUTH_HELPER-HR-IV02",
                    "Request to the provided endpoint is prohibited.",
                    "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                    " attribute while initializing the SDK. The specified endpoint in this request " +
                    "cannot be found among the `resourceServerURLs`"
                )
            );
        }
    }

    public async httpRequestAll(
        requestConfigs: HttpRequestConfig[],
        httpClient: HttpClientInstance,
        isHttpHandlerEnabled?: boolean,
        httpErrorCallback?: (error: HttpError) => void | Promise<void>,
        httpFinishCallback?: () => void
    ): Promise<HttpResponse[] | undefined> {
        let matches = true;
        const config = await this._dataLayer.getConfigData();
    
        for (const requestConfig of requestConfigs) {
            let urlMatches = false;
    
            for (const baseUrl of [
                ...((await config)?.resourceServerURLs ?? []),
                (config as any).baseUrl
            ]) {
                if (baseUrl && requestConfig.url?.startsWith(baseUrl)) {
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
                requests.push(httpClient.request(request));
            });
    
            return (
                httpClient?.all &&
                httpClient
                    .all(requests)
                    .then((responses: HttpResponse[]) => {
                        return Promise.resolve(responses);
                    })
                    .catch(async (error: HttpError) => {
                        if (error?.response?.status === 401 || !error?.response) {
                            let refreshTokenResponse: TokenResponse | BasicUserInfo;
                            try {
                                refreshTokenResponse = await this._authenticationClient.refreshAccessToken();
                            } catch (refreshError: any) {
                                if (isHttpHandlerEnabled) {
                                    if (typeof httpErrorCallback === "function") {
                                        await httpErrorCallback({
                                            ...error,
                                            code: ACCESS_TOKEN_INVALID
                                        });
                                    }
                                    if (typeof httpFinishCallback === "function") {
                                        httpFinishCallback();
                                    }
                                }
                
                                throw new AsgardeoAuthException(
                                    "SPA-AUTH_HELPER-HRA-SE01",
                                    refreshError?.name ?? "Refresh token request failed.",
                                    refreshError?.message ??
                                        "An error occurred while trying to refresh the " +
                                        "access token following a 401 response from the server."
                                );
                            }
            
                        if (refreshTokenResponse) {
                            return (
                                httpClient.all &&
                                httpClient
                                    .all(requests)
                                    .then((response) => {
                                        return Promise.resolve(response);
                                    })
                                    .catch(async (error) => {
                                        if (isHttpHandlerEnabled) {
                                            if (typeof httpErrorCallback === "function") {
                                                await httpErrorCallback(error);
                                            }
                                            if (typeof httpFinishCallback === "function") {
                                                httpFinishCallback();
                                            }
                                        }
                
                                        return Promise.reject(error);
                                    })
                            );
                        }
                        }
            
                        if (isHttpHandlerEnabled) {
                            if (typeof httpErrorCallback === "function") {
                                await httpErrorCallback(error);
                            }
                            if (typeof httpFinishCallback === "function") {
                                httpFinishCallback();
                            }
                        }
            
                        return Promise.reject(error);
                    })
            );
        } else {
            throw new AsgardeoAuthException(
                "SPA-AUTH_HELPER-HRA-IV02",
                "Request to the provided endpoint is prohibited.",
                "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                " attribute while initializing the SDK. The specified endpoint in this request " +
                "cannot be found among the `resourceServerURLs`"
            );
        }
    }

    public async requestAccessToken(
        authorizationCode?: string,
        sessionState?: string,
        checkSession?: () => Promise<void>,
        pkce?: string,
        state?: string
    ): Promise<BasicUserInfo> {
        const config = await this._dataLayer.getConfigData();

        if (config.storage === Storage.BrowserMemory && config.enablePKCE && sessionState) {
            const pkce = SPAUtils.getPKCE(
                AuthenticationUtils.extractPKCEKeyFromStateParam(sessionState)
            );

            await this._authenticationClient.setPKCECode(
                AuthenticationUtils.extractPKCEKeyFromStateParam(sessionState),
                pkce
            );
        } else if (config.storage === Storage.WebWorker && pkce) {
            await this._authenticationClient.setPKCECode(pkce, state ?? "");
        }

        if (authorizationCode) {
            return this._authenticationClient
                .requestAccessToken(authorizationCode, sessionState ?? "", state ?? "")
                .then(async () => {
                    // Disable this temporarily
                    /* if (config.storage === Storage.BrowserMemory) {
                        SPAUtils.setSignOutURL(await _authenticationClient.getSignOutURL());
                    } */
                    if (config.storage !== Storage.WebWorker) {
                        SPAUtils.setSignOutURL(await this._authenticationClient.getSignOutURL());

                        if (this._spaHelper) {
                            this._spaHelper.clearRefreshTokenTimeout();
                            this._spaHelper.refreshAccessTokenAutomatically(this);
                        }

                        // Enable OIDC Sessions Management only if it is set to true in the config.
                        if (
                            checkSession && 
                            typeof checkSession === "function" && 
                            config.enableOIDCSessionManagement
                        ) {
                            checkSession();
                        }
                    } else {
                        if (this._spaHelper) {
                            this._spaHelper.refreshAccessTokenAutomatically(this);
                        }
                    }

                    return this._authenticationClient.getBasicUserInfo();
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return Promise.reject(
            new AsgardeoAuthException(
                "SPA-AUTH_HELPER-RAT1-NF01",
                "No authorization code.",
                "No authorization code was found."
            )
        );
    }

    public async trySignInSilently(
        constructSilentSignInUrl: () => Promise<string>,
        requestAccessToken: (authzCode: string, sessionState: string, state: string) => Promise<BasicUserInfo>,
        sessionManagementHelper: SessionManagementHelperInterface
    ): Promise<BasicUserInfo | boolean> {

        // This block is executed by the iFrame when the server redirects with the authorization code.
        if (SPAUtils.isInitializedSilentSignIn()) {
            await sessionManagementHelper.receivePromptNoneResponse();

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

        // This gets executed in the main thread and sends the prompt none request.
        const rpIFrame = document.getElementById(RP_IFRAME) as HTMLIFrameElement;

        const promptNoneIFrame: HTMLIFrameElement = rpIFrame?.contentDocument?.getElementById(
            PROMPT_NONE_IFRAME
        ) as HTMLIFrameElement;

        try {
            const url = await constructSilentSignInUrl();

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
                    requestAccessToken(data?.data?.code, data?.data?.sessionState, data?.data?.state)
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
    }

    public async handleSignIn (
        shouldStopAuthn: () => Promise<boolean>,
        checkSession: () => Promise<void>,
        tryRetrievingUserInfo?: () => Promise<BasicUserInfo | undefined>
    ): Promise<BasicUserInfo | undefined> {
        const config = await this._dataLayer.getConfigData();

        if (await shouldStopAuthn()) {
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

        if (config.storage !== Storage.WebWorker) {
            if (await this._authenticationClient.isAuthenticated()) {
                this._spaHelper.clearRefreshTokenTimeout();
                this._spaHelper.refreshAccessTokenAutomatically(this);

                // Enable OIDC Sessions Management only if it is set to true in the config.
                if (config.enableOIDCSessionManagement) {
                    checkSession();
                }

                return Promise.resolve(await this._authenticationClient.getBasicUserInfo());
            }
        }

        const error = new URL(window.location.href).searchParams.get(ERROR);
        const errorDescription = new URL(window.location.href).searchParams.get(ERROR_DESCRIPTION);

        if (error) {
            const url = new URL(window.location.href);
            url.searchParams.delete(ERROR);
            url.searchParams.delete(ERROR_DESCRIPTION);

            history.pushState(null, document.title, url.toString());

            throw new AsgardeoAuthException("SPA-AUTH_HELPER-SI-SE01", error, errorDescription ?? "");
        }

        if (config.storage === Storage.WebWorker && tryRetrievingUserInfo) {
            const basicUserInfo = await tryRetrievingUserInfo();

            if (basicUserInfo) {
                return basicUserInfo;
            }
        }
    }

    public async attachTokenToRequestConfig(request : HttpRequestConfig): Promise<void> {
        const requestConfig = { attachToken: true, ...request };
        if (requestConfig.attachToken) {
            if(requestConfig.shouldAttachIDPAccessToken) {
                request.headers = {
                    ...request.headers,
                    Authorization: `Bearer ${ await this.getIDPAccessToken() }`
                };
            } else {
                request.headers = {
                    ...request.headers,
                    Authorization: `Bearer ${ await this.getAccessToken() }`
                };
            }
        }
    }

    public async getBasicUserInfo(): Promise<BasicUserInfo> {
        return this._authenticationClient.getBasicUserInfo();
    }

    public async getDecodedIDToken(): Promise<DecodedIDTokenPayload> {
        return this._authenticationClient.getDecodedIDToken();
    }

    public async getDecodedIDPIDToken(): Promise<DecodedIDTokenPayload> {
        return this._authenticationClient.getDecodedIDToken();
    }

    public async getCryptoHelper(): Promise<CryptoHelper> {
        return this._authenticationClient.getCryptoHelper();
    }

    public async getIDToken(): Promise<string> {
        return this._authenticationClient.getIDToken();
    }

    public async getOIDCServiceEndpoints(): Promise<OIDCEndpoints> {
        return this._authenticationClient.getOIDCServiceEndpoints();
    }

    public async getAccessToken(): Promise<string> {
        return this._authenticationClient.getAccessToken();
    }

    public async getIDPAccessToken(): Promise<string> {
        return (await this._dataLayer.getSessionData())?.access_token;
    }

    public getDataLayer(): DataLayer<T> {
        return this._dataLayer;
    }

    public async isAuthenticated(): Promise<boolean> {
        return this._authenticationClient.isAuthenticated();
    }
}

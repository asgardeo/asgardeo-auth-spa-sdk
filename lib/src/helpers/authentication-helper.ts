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
    CustomGrantConfig, 
    DataLayer, 
    FetchResponse, 
    TokenResponse
} from "@asgardeo/auth-js";
import { SPAHelper } from "./spa-helper";
import { SPAUtils } from "..";
import { ACCESS_TOKEN_INVALID, CUSTOM_GRANT_CONFIG, Storage } from "../constants";
import {
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
    private _authenticationClient: AsgardeoAuthClient<T>;
    private _dataLayer: DataLayer<T>;
    public constructor(authClient: AsgardeoAuthClient<T>) {
        this._authenticationClient = authClient;
        this._dataLayer = this._authenticationClient.getDataLayer();
    }

    public async attachToken(request: HttpRequestConfig): Promise<void> {
        const requestConfig = { attachToken: true, ...request };
        if (requestConfig.attachToken) {
            request.headers = {
            ...request.headers,
            Authorization: `Bearer ${await this._authenticationClient.getAccessToken()}`
            };
        }
    }

    public setHttpRequestStartCallback(
        _httpClient: HttpClientInstance,
        callback: () => void
    ): void {
        _httpClient?.setHttpRequestStartCallback &&
        _httpClient.setHttpRequestStartCallback(callback);
    }

    public setHttpRequestSuccessCallback(
        _httpClient: HttpClientInstance,
        callback: (response: HttpResponse) => void
    ): void {
        _httpClient?.setHttpRequestSuccessCallback &&
        _httpClient.setHttpRequestSuccessCallback(callback);
    }

    public setHttpRequestFinishCallback(
        _httpClient: HttpClientInstance,
        callback: () => void
    ): void {
        _httpClient?.setHttpRequestFinishCallback && 
        _httpClient.setHttpRequestFinishCallback(callback);
    }

    public async requestCustomGrant(
        config: SPACustomGrantConfig,
        spaHelper: SPAHelper<WebWorkerClientConfig | MainThreadClientConfig>,
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
                            spaHelper.refreshAccessTokenAutomatically();
                
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
        spaHelper: SPAHelper<WebWorkerClientConfig | MainThreadClientConfig>,
        enableRetrievingSignOutURLFromSession?: (config: SPACustomGrantConfig) => void
    ): Promise<BasicUserInfo> {
        try {
            await this._authenticationClient.refreshAccessToken();
            const customGrantConfig = await this.getCustomGrantConfigData();
            if (customGrantConfig) {
                await this.requestCustomGrant(
                        customGrantConfig, 
                        spaHelper, 
                        enableRetrievingSignOutURLFromSession
                    );
            }
            spaHelper.refreshAccessTokenAutomatically();

            return this._authenticationClient.getBasicUserInfo();
        } catch (error) {
            return Promise.reject(error);
        }
    }

    public async httpRequest(
        httpClient: HttpClientInstance,
        requestConfig: HttpRequestConfig,
        spaHelper: SPAHelper<WebWorkerClientConfig | MainThreadClientConfig>,
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
                        // Try to refresh the token
                        let refreshAccessTokenResponse: BasicUserInfo;
                        try {
                            refreshAccessTokenResponse = await this.refreshAccessToken(
                                spaHelper, 
                                enableRetrievingSignOutURLFromSession
                            );
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
                    "SPA-WORKER_CORE-HR-IV02",
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

    public requestAccessToken = async (
        authorizationCode?: string,
        sessionState?: string,
        checkSession?: () => Promise<void>,
        spaHelper?: SPAHelper<WebWorkerClientConfig | MainThreadClientConfig>,
        pkce?: string,
        state?: string
    ): Promise<BasicUserInfo> => {
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

                        if (spaHelper) {
                            spaHelper.clearRefreshTokenTimeout();
                            spaHelper.refreshAccessTokenAutomatically();
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
                        if (spaHelper) {
                            spaHelper.refreshAccessTokenAutomatically();
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
                "SPA-WORKER_CORE-RAT1-NF01",
                "No authorization code.",
                "No authorization code was found."
            )
        );
    };
}

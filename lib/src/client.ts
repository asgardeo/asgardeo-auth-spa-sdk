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
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    OIDCEndpoints
} from "@asgardeo/auth-js";
import { MainThreadClient, WebWorkerClient } from "./clients";
import { Hooks, Storage } from "./constants";
import { AsgardeoSPAException } from "./exception";
import { HttpClientInstance } from "./http-client";
import {
    AuthSPAClientConfig,
    Config,
    HttpRequestConfig,
    HttpResponse,
    MainThreadClientConfig,
    MainThreadClientInterface,
    SignInConfig,
    WebWorkerClientConfig,
    WebWorkerClientInterface
} from "./models";
import { SPAUtils } from "./utils";

/**
 * Default configurations.
 */
const DefaultConfig: Partial<AuthClientConfig<Config>> = {
    checkSessionInterval: 3,
    clientHost: origin,
    enableOIDCSessionManagement: false,
    sessionRefreshInterval: 300,
    storage: Storage.SessionStorage
};

const PRIMARY_INSTANCE = "primaryInstance";

/**
 * This class provides the necessary methods to implement authentication in a Single Page Application.
 *
 * @export
 * @class AsgardeoSPAClient
 */
export class AsgardeoSPAClient {
    private static _instances: Map<string, AsgardeoSPAClient> = new Map<string, AsgardeoSPAClient>();
    private _client: WebWorkerClientInterface | MainThreadClientInterface | undefined;
    private _storage: Storage | undefined;
    private _initialized: boolean = false;
    private _startedInitialize: boolean = false;
    private _onSignInCallback: (response: BasicUserInfo) => void = () => null;
    private _onSignOutCallback: () => void = () => null;
    private _onEndUserSession: (response: any) => void = () => null;
    private _onInitialize: (response: boolean) => void = () => null;
    private _onCustomGrant: Map<string, (response: any) => void> = new Map();
    private _instanceID: string;

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor(id: string) {
        this._instanceID = id;
    }

    /**
     * This method specifies if the `AsgardeoSPAClient` has been initialized or not.
     *
     * @return {Promise<boolean>} - Resolves to `true` if the client has been initialized.
     *
     * @memberof AsgardeoSPAClient
     *
     * @private
     */
    private async _isInitialized(): Promise<boolean> {
        if (!this._startedInitialize) {
            return false;
        }

        let iterationToWait = 0;

        const sleep = (): Promise<any> => {
            return new Promise((resolve) => setTimeout(resolve, 1000));
        };

        while (!this._initialized) {
            if (iterationToWait === 10) {
                // eslint-disable-next-line no-console
                console.warn("It is taking longer than usual for the object to be initialized");
            }
            await sleep();
            iterationToWait++;
        }

        return true;
    }

    /**
     *  This method checks if the SDK is initialized and the user is authenticated.
     *
     * @return {Promise<boolean>} - A Promise that resolves with `true` if the SDK is initialized and the
     * user is authenticated.
     *
     * @memberof AsgardeoSPAClient
     *
     * @private
     */
    private async _validateMethod(): Promise<boolean> {
        if (!(await this._isInitialized())) {
            return Promise.reject();
        }

        if (!(await this.isAuthenticated())) {
            return Promise.reject();
        }

        return true;
    }

    /**
     * This method returns the instance of the singleton class.
     *
     * @return {AsgardeoSPAClient} - Returns the instance of the singleton class.
     *
     * @example
     * ```
     * const auth = AsgardeoSPAClient.getInstance();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#getinstance
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public static getInstance(id?: string): AsgardeoSPAClient | undefined {
        if (id && this._instances?.get(id)) {
            return this._instances.get(id);
        } else if (!id && this._instances?.get(PRIMARY_INSTANCE)) {
            return this._instances.get(PRIMARY_INSTANCE);
        }

        if (id) {
            this._instances.set(id, new AsgardeoSPAClient(id));

            return this._instances.get(id);
        }

        this._instances.set(PRIMARY_INSTANCE, new AsgardeoSPAClient(PRIMARY_INSTANCE));

        return this._instances.get(PRIMARY_INSTANCE);
    }

    /**
     * This method initializes the `AsgardeoSPAClient` instance.
     *
     * @param {ConfigInterface} config The config object to initialize with.
     *
     * @return {Promise<boolean>} - Resolves to `true` if initialization is successful.
     *
     * @example
     * ```
     * auth.initialize({
     *     signInRedirectURL: "http://localhost:3000/sign-in",
     *     clientID: "client ID",
     *     serverOrigin: "https://localhost:9443"
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#initialize
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async initialize(config: AuthSPAClientConfig): Promise<boolean> {
        this._storage = config.storage ?? Storage.SessionStorage;
        this._initialized = false;
        this._startedInitialize = true;

        if (!(this._storage === Storage.WebWorker)) {
            if (!this._client) {
                const mainThreadClientConfig = config as AuthClientConfig<MainThreadClientConfig>;
                const defaultConfig = { ...DefaultConfig } as Partial<AuthClientConfig<MainThreadClientConfig>>;
                this._client = await MainThreadClient({ ...defaultConfig, ...mainThreadClientConfig });
            }

            this._initialized = true;

            if (this._onInitialize) {
                this._onInitialize(true);
            }

            return Promise.resolve(true);
        } else {
            if (!this._client) {
                const webWorkerClientConfig = config as AuthClientConfig<WebWorkerClientConfig>;
                this._client = WebWorkerClient({
                    ...DefaultConfig,
                    ...webWorkerClientConfig
                }) as WebWorkerClientInterface;

                return this._client
                    .initialize()
                    .then(() => {
                        if (this._onInitialize) {
                            this._onInitialize(true);
                        }
                        this._initialized = true;

                        return Promise.resolve(true);
                    })
                    .catch((error) => {
                        return Promise.reject(error);
                    });
            }

            return Promise.resolve(true);
        }
    }

    /**
     * This method returns a Promise that resolves with the basic user information obtained from the ID token.
     *
     * @return {Promise<BasicUserInfo>} - A promise that resolves with the user information.
     *
     * @example
     * ```
     * auth.getBasicUserInfo().then((response) => {
     *    // console.log(response);
     * }).catch((error) => {
     *    // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#getuserinfo
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getBasicUserInfo(): Promise<BasicUserInfo | undefined> {
        await this._validateMethod();

        return this._client?.getBasicUserInfo();
    }

    /**
     * This method initiates the authentication flow. This should be called twice.
     *  1. To initiate the authentication flow.
     *  2. To obtain the access token after getting the authorization code.
     *
     * To satisfy the second condition, one of the two strategies mentioned below can be used:
     *  1. Redirect the user back to the same login page that initiated the authentication flow.
     *  2. Call the `signIn()` method in the page the user is redirected to after authentication.
     *
     * **To fire a callback function after signing in, use the `on()` method.**
     * **To learn more about the `on()` method:**
     * @see {@link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#on}
     *
     * @param {SignInConfig} config - The sign-in config.
     * The `SignInConfig` object has these two attributes in addition to any custom key-value pairs.
     *  1. fidp - Specifies the FIDP parameter that is used to take the user directly to an IdP login page.
     *  2. forceInit: Specifies if the OIDC Provider Meta Data should be loaded again from the `well-known`
     * endpoint.
     *  3. Any other parameters that should be appended to the authorization request.
     *
     * @return {Promise<BasicUserInfo>} - A promise that resolves with the user information.
     *
     * @example
     * ```
     * auth.signIn();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#signin
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async signIn(
        config?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo | undefined> {
        await this._isInitialized();

        // Discontinues the execution of this method if `config.callOnlyOnRedirect` is true and the `signIn` method
        // is not being called on redirect.
        if (!SPAUtils.canContinueSignIn(Boolean(config?.callOnlyOnRedirect), authorizationCode)) {
            return;
        }

        delete config?.callOnlyOnRedirect;

        return this._client?.signIn(config, authorizationCode, sessionState).then((response: BasicUserInfo) => {
            if (this._onSignInCallback) {
                if (response.allowedScopes || response.displayName || response.email || response.username) {
                    this._onSignInCallback(response);
                }
            }

            return response;
        });
    }

    /**
     * This method allows you to sign in silently.
     * First, this method sends a prompt none request to see if there is an active user session in the identity server.
     * If there is one, then it requests the access token and stores it. Else, it returns false.
     *
     * If this method is to be called on page load and the `signIn` method is also to be called on page load,
     * then it is advisable to call this method after the `signIn` call.
     *
     * @return {Promise<BasicUserInfo | boolean>} - A Promise that resolves with the user information after signing in
     * or with `false` if the user is not signed in.
     *
     * @example
     *```
     * auth.trySignInSilently()
     *```
     */
    public async trySignInSilently(): Promise<BasicUserInfo | boolean | undefined> {
        await this._isInitialized();

        // checks if the `signIn` method has been called.
        if (SPAUtils.wasSignInCalled()) {
            return;
        }

        return this._client?.trySignInSilently().then((response: BasicUserInfo | boolean) => {
            if (this._onSignInCallback && response) {
                const basicUserInfo = response as BasicUserInfo;
                if (
                    basicUserInfo.allowedScopes ||
                    basicUserInfo.displayName ||
                    basicUserInfo.email ||
                    basicUserInfo.username
                ) {
                    this._onSignInCallback(basicUserInfo);
                }
            }

            return response;
        });
    }

    /**
     * This method initiates the sign-out flow.
     *
     * **To fire a callback function after signing out, use the `on()` method.**
     * **To learn more about the `on()` method:**
     * @see {@link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#on}
     *
     * @return {Promise<boolean>} - Returns a promise that resolves with `true` if sign out is successful.
     *
     * @example
     * ```
     * auth.signOut();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#signout
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async signOut(): Promise<boolean> {
        await this._validateMethod();

        const signOutResponse = (await this._client?.signOut()) ?? false;

        return signOutResponse;
    }

    /**
     * This method sends an API request to a protected endpoint.
     * The access token is automatically attached to the header of the request.
     * This is the only way by which protected endpoints can be accessed
     * when the web worker is used to store session information.
     *
     * @param {HttpRequestConfig} config -  The config object containing attributes necessary to send a request.
     *
     * @return {Promise<HttpResponse>} - Returns a Promise that resolves with the response to the request.
     *
     * @example
     * ```
     *  const requestConfig = {
     *      headers: {
     *          "Accept": "application/json",
     *          "Access-Control-Allow-Origin": "https://localhost:9443/myaccount",
     *          "Content-Type": "application/scim+json"
     *      },
     *      method: "GET",
     *      url: "https://localhost:9443/scim2/me"
     *  };
     *
     *  return auth.httpRequest(requestConfig)
     *     .then((response) => {
     *           // console.log(response);
     *      })
     *      .catch((error) => {
     *           // console.error(error);
     *      });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#httprequest
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async httpRequest(config: HttpRequestConfig): Promise<HttpResponse | undefined> {
        await this._validateMethod();

        return this._client?.httpRequest(config);
    }

    /**
     * This method sends multiple API requests to a protected endpoint.
     * The access token is automatically attached to the header of the request.
     * This is the only way by which multiple requests can be sent to protected endpoints
     * when the web worker is used to store session information.
     *
     * @param {HttpRequestConfig[]} config -  The config object containing attributes necessary to send a request.
     *
     * @return {Promise<HttpResponse[]>} - Returns a Promise that resolves with the responses to the requests.
     *
     * @example
     * ```
     *  const requestConfig = {
     *      headers: {
     *          "Accept": "application/json",
     *          "Content-Type": "application/scim+json"
     *      },
     *      method: "GET",
     *      url: "https://localhost:9443/scim2/me"
     *  };
     *
     *  const requestConfig2 = {
     *      headers: {
     *          "Accept": "application/json",
     *          "Content-Type": "application/scim+json"
     *      },
     *      method: "GET",
     *      url: "https://localhost:9443/scim2/me"
     *  };
     *
     *  return auth.httpRequest([requestConfig, requestConfig2])
     *     .then((responses) => {
     *           response.forEach((response)=>{
     *              // console.log(response);
     *           });
     *      })
     *      .catch((error) => {
     *           // console.error(error);
     *      });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#httprequestall
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async httpRequestAll(config: HttpRequestConfig[]): Promise<HttpResponse[] | undefined> {
        await this._validateMethod();

        return this._client?.httpRequestAll(config);
    }

    /**
     * This method allows you to send a request with a custom grant.
     *
     * @param {CustomGrantRequestParams} config - The request parameters.
     *
     * @return {Promise<HttpResponse<any> | SignInResponse>} - A Promise that resolves with
     * the value returned by the custom grant request.
     *
     * @example
     * ```
     * auth.customGrant({
     *   attachToken: false,
     *   data: {
     *       client_id: "{{clientId}}",
     *       grant_type: "account_switch",
     *       scope: "{{scope}}",
     *       token: "{{token}}",
     *   },
     *   id: "account-switch",
     *   returnResponse: true,
     *   returnsSession: true,
     *   signInRequired: true
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#customgrant
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async requestCustomGrant(config: CustomGrantConfig): Promise<HttpResponse<any> | BasicUserInfo | undefined> {
        if (config.signInRequired) {
            await this._validateMethod();
        } else {
            await this._validateMethod();
        }

        if (!config.id) {
            return Promise.reject(
                new AsgardeoSPAException(
                    "AUTH_CLIENT-RCG-NF01",
                    "client",
                    "requestCustomGrant",
                    "The custom grant request id not found.",
                    "The id attribute of the custom grant config object passed as an argument should have a value."
                )
            );
        }

        const customGrantResponse = await this._client?.requestCustomGrant(config);

        const customGrantCallback = this._onCustomGrant.get(config.id);
        customGrantCallback && customGrantCallback(this._onCustomGrant?.get(config.id));

        return customGrantResponse;
    }

    /**
     * This method ends a user session. The access token is revoked and the session information is destroyed.
     *
     * **To fire a callback function after ending user session, use the `on()` method.**
     * **To learn more about the `on()` method:**
     * @see {@link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#on}
     *
     * @return {Promise<boolean>} - A promise that resolves with `true` if the process is successful.
     *
     * @example
     * ```
     * auth.endUserSession();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#endusersession
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async revokeAccessToken(): Promise<boolean | undefined> {
        await this._validateMethod();

        const revokeAccessToken = await this._client?.revokeAccessToken();
        this._onEndUserSession && await this._onEndUserSession(revokeAccessToken);

        return revokeAccessToken;
    }

    /**
     * This method returns a Promise that resolves with an object containing the service endpoints.
     *
     * @return {Promise<ServiceResourcesType} - A Promise that resolves with an object containing the service endpoints.
     *
     * @example
     * ```
     * auth.getServiceEndpoints().then((endpoints) => {
     *      // console.log(endpoints);
     *  }).error((error) => {
     *      // console.error(error);
     *  });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#getserviceendpoints
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getOIDCServiceEndpoints(): Promise<OIDCEndpoints | undefined> {
        await this._isInitialized();

        return this._client?.getOIDCServiceEndpoints();
    }

    /**
     * This methods returns the Axios http client.
     *
     * @return {HttpClientInstance} - The Axios HTTP client.
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public getHttpClient(): HttpClientInstance {
        if (this._client) {
            if (this._storage !== Storage.WebWorker) {
                const mainThreadClient = this._client as MainThreadClientInterface;
                return mainThreadClient.getHttpClient();
            }

            throw new AsgardeoSPAException(
                "AUTH_CLIENT-GHC-IV01",
                "client",
                "getHttpClient",
                "Http client cannot be returned.",
                "The http client cannot be returned when the storage type is set to webWorker."
            );
        }

        throw new AsgardeoSPAException(
            "AUTH_CLIENT-GHC-NF02",
            "client",
            "getHttpClient",
            "The SDK is not initialized.",
            "The SDK has not been initialized yet. Initialize the SDK suing the initialize method " +
                "before calling this method."
        );
    }

    /**
     * This method decodes the payload of the id token and returns it.
     *
     * @return {Promise<DecodedIdTokenPayloadInterface>} - A Promise that resolves with
     * the decoded payload of the id token.
     *
     * @example
     * ```
     * auth.getDecodedIDToken().then((response)=>{
     *     // console.log(response);
     * }).catch((error)=>{
     *     // console.error(error);
     * });
     * ```
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#getdecodedidtoken
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getDecodedIDToken(): Promise<DecodedIDTokenPayload | undefined> {
        await this._validateMethod();

        return this._client?.getDecodedIDToken();
    }

    /**
     * This method return the ID token.
     *
     * @return {Promise<string>} - A Promise that resolves with the ID token.
     *
     * @example
     * ```
     * const idToken = await auth.getIDToken();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master#getIDToken
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public async getIDToken(): Promise<string | undefined> {
        await this._validateMethod();

        return this._client?.getIDToken();
    }

    /**
     * This method return a Promise that resolves with the access token.
     *
     * **This method will not return the access token if the storage type is set to `webWorker`.**
     *
     * @return {Promise<string>} - A Promise that resolves with the access token.
     *
     * @example
     * ```
     *   auth.getAccessToken().then((token) => {
     *       // console.log(token);
     *   }).catch((error) => {
     *       // console.error(error);
     *   });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#getaccesstoken
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getAccessToken(): Promise<string> {
        await this._validateMethod();

        if (this._storage && [(Storage.WebWorker, Storage.BrowserMemory)].includes(this._storage)) {
            return Promise.reject(
                new AsgardeoSPAException(
                    "AUTH_CLIENT-GAT-IV01",
                    "client",
                    "getAccessToken",
                    "The access token cannot be returned.",
                    "The access token cannot be returned when the storage type is set to webWorker or browserMemory."
                )
            );
        }
        const mainThreadClient = this._client as MainThreadClientInterface;

        return mainThreadClient.getAccessToken();
    }

    /**
     * This method refreshes the access token.
     *
     * @return {TokenResponseInterface} - A Promise that resolves with an object containing
     * information about the refreshed access token.
     *
     * @example
     * ```
     * auth.refreshToken().then((response)=>{
     *      // console.log(response);
     * }).catch((error)=>{
     *      // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#refreshtoken
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async refreshAccessToken(): Promise<BasicUserInfo | undefined> {
        await this._validateMethod();

        return this._client?.refreshAccessToken();
    }

    /**
     * This method specifies if the user is authenticated or not.
     *
     * @return {Promise<boolean>} - A Promise that resolves with `true` if the user is authenticated.
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async isAuthenticated(): Promise<boolean | undefined> {
        await this._isInitialized();

        return this._client?.isAuthenticated();
    }

    /**
     * This method attaches a callback function to an event hook that fires the callback when the event happens.
     *
     * @param {Hooks.CustomGrant} hook - The name of the hook.
     * @param {(response?: any) => void} callback - The callback function.
     * @param {string} id (optional) - The id of the hook. This is used when multiple custom grants are used.
     *
     * @example
     * ```
     * auth.on("sign-in", (response)=>{
     *      // console.log(response);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#on
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async on(hook: Hooks.CustomGrant, callback: (response?: any) => void, id: string): Promise<void>;
    public async on(
        hook:
            | Hooks.RevokeAccessToken
            | Hooks.HttpRequestError
            | Hooks.HttpRequestFinish
            | Hooks.HttpRequestStart
            | Hooks.HttpRequestSuccess
            | Hooks.Initialize
            | Hooks.SignIn
            | Hooks.SignOut,
        callback: (response?: any) => void
    ): Promise<void>;
    public async on(hook: Hooks, callback: (response?: any) => void, id?: string): Promise<void> {
        await this._isInitialized();
        if (callback && typeof callback === "function") {
            switch (hook) {
                case Hooks.SignIn:
                    this._onSignInCallback = callback;
                    break;
                case Hooks.SignOut:
                    this._onSignOutCallback = callback;
                    if (SPAUtils.isSignOutSuccessful()) {
                        this._onSignOutCallback();
                    }
                    break;
                case Hooks.RevokeAccessToken:
                    this._onEndUserSession = callback;
                    break;
                case Hooks.Initialize:
                    this._onInitialize = callback;
                    break;
                case Hooks.HttpRequestError:
                    this._client?.setHttpRequestErrorCallback(callback);
                    break;
                case Hooks.HttpRequestFinish:
                    this._client?.setHttpRequestFinishCallback(callback);
                    break;
                case Hooks.HttpRequestStart:
                    this._client?.setHttpRequestStartCallback(callback);
                    break;
                case Hooks.HttpRequestSuccess:
                    this._client?.setHttpRequestSuccessCallback(callback);
                    break;
                case Hooks.CustomGrant:
                    id && this._onCustomGrant.set(id, callback);
                    break;
                default:
                    throw new AsgardeoSPAException(
                        "AUTH_CLIENT-ON-IV01",
                        "client",
                        "on",
                        "Invalid hook.",
                        "The provided hook is invalid."
                    );
            }
        } else {
            throw new AsgardeoSPAException(
                "AUTH_CLIENT-ON-IV02",
                "client",
                "on",
                "Invalid callback function.",
                "The provided callback function is invalid."
            );
        }
    }

    /**
     * This method enables callback functions attached to the http client.
     *
     * @return {Promise<boolean>} - A promise that resolves with True.
     *
     * @example
     * ```
     * auth.enableHttpHandler();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#enableHttpHandler
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async enableHttpHandler(): Promise<boolean | undefined> {
        await this._isInitialized();

        return this._client?.enableHttpHandler();
    }

    /**
     * This method disables callback functions attached to the http client.
     *
     * @return {Promise<boolean>} - A promise that resolves with True.
     *
     * @example
     * ```
     * auth.disableHttpHandler();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master#disableHttpHandler
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async disableHttpHandler(): Promise<boolean | undefined> {
        await this._isInitialized();

        return this._client?.disableHttpHandler();
    }

    /**
     * This method updates the configuration that was passed into the constructor when instantiating this class.
     *
     * @param {Partial<AuthClientConfig<T>>} config - A config object to update the SDK configurations with.
     *
     * @example
     * ```
     * const config = {
     *     signInRedirectURL: "http://localhost:3000/sign-in",
     *     clientID: "client ID",
     *     serverOrigin: "https://localhost:9443"
     * }
     * const auth.updateConfig(config);
     * ```
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib#updateConfig
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public async updateConfig(config: Partial<AuthClientConfig<Config>>): Promise<void> {
        await this._isInitialized();
        if (this._storage === Storage.WebWorker) {
            const client = this._client as WebWorkerClientInterface;
            await client.updateConfig(config as Partial<AuthClientConfig<WebWorkerClientConfig>>);
        } else {
            const client = this._client as WebWorkerClientInterface;
            await client.updateConfig(config as Partial<AuthClientConfig<WebWorkerClientConfig>>);
        }

        return;
    }
}

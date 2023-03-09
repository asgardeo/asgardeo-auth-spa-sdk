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

import { AuthClientConfig } from "@asgardeo/auth-js";
import { Storage } from "../constants";


export interface SPAConfig {
    /**
     * Enable OIDC Session Management with PR Iframe.
     * @remarks If the consumer app the OP is hosted in different domains,
     * third party cookies has to be enabled for this to work properly.
     */
    enableOIDCSessionManagement?: boolean;
    checkSessionInterval?: number;
    sessionRefreshInterval?: number;
    resourceServerURLs?: string[];
    periodicTokenRefresh?: boolean;
}

/**
 * SDK Client config parameters.
 */
export interface MainThreadClientConfig extends SPAConfig {
    storage?: Storage.SessionStorage | Storage.LocalStorage | Storage.BrowserMemory;
}

export interface WebWorkerClientConfig  extends SPAConfig {
    storage: Storage.WebWorker;
    requestTimeout?: number;
}

export type Config = MainThreadClientConfig | WebWorkerClientConfig;

export type AuthSPAClientConfig = AuthClientConfig<Config>;

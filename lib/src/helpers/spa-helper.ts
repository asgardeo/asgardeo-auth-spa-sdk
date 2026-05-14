/**
 * Copyright (c) 2020-2026, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import { AsgardeoAuthClient, DataLayer, REFRESH_TOKEN_TIMER } from "@asgardeo/auth-js";

import { AuthenticationHelper, MainThreadClientConfig, WebWorkerClientConfig } from "../";

export class SPAHelper<T extends MainThreadClientConfig | WebWorkerClientConfig> {
    private _authenticationClient: AsgardeoAuthClient<T>;
    private _dataLayer: DataLayer<T>;
    private _isTokenRefreshLoading: boolean = false;

    public constructor(authClient: AsgardeoAuthClient<T>) {
        this._authenticationClient = authClient;
        this._dataLayer = this._authenticationClient.getDataLayer();
    }

    public async refreshAccessTokenAutomatically(
        authenticationHelper: AuthenticationHelper<
          MainThreadClientConfig | WebWorkerClientConfig
        >
      ): Promise<void> {
        const shouldRefreshAutomatically: boolean = (await this._dataLayer.getConfigData())?.periodicTokenRefresh ?? 
            false;
        
        if (!shouldRefreshAutomatically) {
            return;
        }

        const sessionData = await this._dataLayer.getSessionData();
        if (sessionData.refresh_token) {
            if (sessionData.created_at == null || sessionData.expires_in == null) {
                return;
            }

            const TOKEN_REFRESH_BUFFER_MS = 10_000;
            // Refresh 10 seconds before the expiry time
            const absoluteExpiryTime = sessionData.created_at + parseInt(sessionData.expires_in) * 1000;
            const timeUntilRefresh = absoluteExpiryTime - Date.now() - TOKEN_REFRESH_BUFFER_MS;

            const timer = setTimeout(async () => {
                if (this._isTokenRefreshLoading) return;

                this._isTokenRefreshLoading = true;

                try {
                    await authenticationHelper.refreshAccessToken();
                } finally {
                    this._isTokenRefreshLoading = false;
                }
            }, timeUntilRefresh);

            await this._dataLayer.setTemporaryDataParameter(REFRESH_TOKEN_TIMER, JSON.stringify(timer));
        }
    }

    public async getRefreshTimeoutTimer(): Promise<number> {
        if (await this._dataLayer.getTemporaryDataParameter(REFRESH_TOKEN_TIMER)) {
            return JSON.parse(
                (await this._dataLayer.getTemporaryDataParameter(REFRESH_TOKEN_TIMER)) as string
            );
        }

        return -1;
    }

    public async clearRefreshTokenTimeout(timer?: number): Promise<void> {
        if (timer) {
            clearTimeout(timer);

            return;
        }

        const refreshTimer: number = await this.getRefreshTimeoutTimer();

        if (refreshTimer !== -1) {
            clearTimeout(refreshTimer);
        }
    }
}

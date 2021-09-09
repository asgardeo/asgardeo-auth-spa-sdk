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

import { AsgardeoAuthClient, PKCE_CODE_VERIFIER, SIGN_OUT_URL } from "@asgardeo/auth-js";
import { INITIALIZED_SIGN_IN, INITIALIZED_SILENT_SIGN_IN, SILENT_SIGN_IN_STATE, STATE } from "../constants";

export class SPAUtils {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() {}

    public static removeAuthorizationCode(): void {
        const url = location.href;

        history.pushState({}, document.title, url.replace(/\?code=.*$/, ""));
    }

    public static getPKCE(): string {
        return sessionStorage.getItem(PKCE_CODE_VERIFIER) ?? "";
    }

    public static setPKCE(pkce: string): void {
        sessionStorage.setItem(PKCE_CODE_VERIFIER, pkce);
    }

    public static setSignOutURL(url: string): void {
        sessionStorage.setItem(SIGN_OUT_URL, url);
    }

    public static getSignOutURL(): string {
        return sessionStorage.getItem(SIGN_OUT_URL) ?? "";
    }

    public static removePKCE(): void {
        sessionStorage.removeItem(PKCE_CODE_VERIFIER);
    }

    public static setInitializedSignIn(callOnlyOnRedirect: boolean): boolean {
        const sessionIsInitialized = sessionStorage.getItem(INITIALIZED_SIGN_IN);
        const isInitialized = sessionIsInitialized ? JSON.parse(sessionIsInitialized) : null;
        if (callOnlyOnRedirect && isInitialized) {
            sessionStorage.setItem(INITIALIZED_SIGN_IN, "false");

            return true;
        } else if (callOnlyOnRedirect) {
            return false;
        } else if (isInitialized) {
            sessionStorage.setItem(INITIALIZED_SIGN_IN, "false");

            return true;
        } else {
            sessionStorage.setItem(INITIALIZED_SIGN_IN, "true");

            return true;
        }
    }

    /**
     * Specifies if `trySilentSignIn` has been called.
     *
     * @returns {boolean} True if the `trySilentSignIn` method has been called once.
     */
    public static setIsInitializedSilentSignIn(): boolean {
        const sessionIsInitialized = sessionStorage.getItem(INITIALIZED_SILENT_SIGN_IN);
        const isInitialized = sessionIsInitialized ? JSON.parse(sessionIsInitialized) : null;

        if (isInitialized) {
            sessionStorage.setItem(INITIALIZED_SILENT_SIGN_IN, "false");

            return true;
        } else {
            sessionStorage.setItem(INITIALIZED_SILENT_SIGN_IN, "true");

            return false;
        }
    }

    /**
     * Specifies if the `signIn` method has been called.
     *
     * @returns {boolean} True if the `signIn` has been called once and `trySilentSignIn` has not been called.
     */
    public static wasSignInCalled(): boolean {
        const sessionIsInitialized = sessionStorage.getItem(INITIALIZED_SIGN_IN);
        const isInitialized = sessionIsInitialized ? JSON.parse(sessionIsInitialized) : null;

        const silentSignIsInitialized = sessionStorage.getItem(INITIALIZED_SILENT_SIGN_IN);
        const isSilentSignInInitialized = silentSignIsInitialized ? JSON.parse(silentSignIsInitialized) : null;

        return isInitialized && !isSilentSignInInitialized;
    }

    public static wasSilentSignInCalled(): boolean {
        const silentSignIsInitialized = sessionStorage.getItem(INITIALIZED_SILENT_SIGN_IN);
        const isSilentSignInInitialized = silentSignIsInitialized ? JSON.parse(silentSignIsInitialized) : null;

        return Boolean(isSilentSignInInitialized);
    }

    public static isSignOutSuccessful(): boolean {
        if (AsgardeoAuthClient.isSignOutSuccessful(window.location.href)) {
            const newUrl = window.location.href.split("?")[0];
            history.pushState({}, document.title, newUrl);

            return true;
        }

        return false;
    }

    public static isStatePresentInURL(): boolean {
        const state = new URL(window.location.href).searchParams.get("state");

        return state === SILENT_SIGN_IN_STATE || state === STATE;
    }

    /**
     * Util function to test if `code` and `session_state` are available in the URL as search params.
     * @since 0.2.0
     *
     * @param params - Search params.
     * @return {boolean}
     */
    public static hasAuthSearchParamsInURL(params: string = window.location.search): boolean {

        const AUTH_CODE_REGEXP: RegExp = /[?&]code=[^&]+/;
        const SESSION_STATE_REGEXP: RegExp = /[?&]session_state=[^&]+/;

        return AUTH_CODE_REGEXP.test(params) && SESSION_STATE_REGEXP.test(params);
   }
}

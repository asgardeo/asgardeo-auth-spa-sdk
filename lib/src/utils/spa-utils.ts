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

import { AsgardeoAuthClient, SIGN_OUT_SUCCESS_PARAM, SIGN_OUT_URL } from "@asgardeo/auth-js";
import { SignOutError } from "..";
import {
    ERROR,
    ERROR_DESCRIPTION,
    INITIALIZED_SILENT_SIGN_IN,
    PROMPT_NONE_REQUEST_SENT,
    SILENT_SIGN_IN_STATE,
    STATE_QUERY
} from "../constants";

export class SPAUtils {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() {}

    public static removeAuthorizationCode(): void {
        const url = location.href;

        history.pushState({}, document.title, url.replace(/\?code=.*$/, ""));
    }

    public static getPKCE(pkceKey: string): string {
        return sessionStorage.getItem(pkceKey) ?? "";
    }

    public static setPKCE(pkceKey: string, pkce: string): void {
        sessionStorage.setItem(pkceKey, pkce);
    }

    public static setSignOutURL(url: string): void {
        sessionStorage.setItem(SIGN_OUT_URL, url);
    }

    public static getSignOutURL(): string {
        return sessionStorage.getItem(SIGN_OUT_URL) ?? "";
    }

    public static removePKCE(pkceKey: string): void {
        sessionStorage.removeItem(pkceKey);
    }

    /**
     * This method is used to discontinue the execution of the `signIn` method if `callOnlyOnRedirect` is true and
     * the method is not called on being redirected from the authorization server.
     *
     * This method can be used to allow the `signIn` method to be called only
     * on being redirected from the authorization server.
     *
     * @param callOnlyOnRedirect {boolean} - True if the method should only be called on redirect.
     * @param authorizationCode {string} - Authorization code.
     *
     * @returns {boolean} - True if the method should be called.
     */
    public static canContinueSignIn(callOnlyOnRedirect: boolean, authorizationCode?: string): boolean {
        if (
            callOnlyOnRedirect &&
            !SPAUtils.hasErrorInURL() &&
            !SPAUtils.hasAuthSearchParamsInURL() &&
            !authorizationCode
        ) {
            return false;
        }

        return true;
    }

    /**
     * Specifies if `trySilentSignIn` has been called.
     *
     * @returns {boolean} True if the `trySilentSignIn` method has been called once.
     */
    public static isInitializedSilentSignIn(): boolean {
        return SPAUtils.isSilentStatePresentInURL();
    }

    /**
     * Specifies if the `signIn` method has been called.
     *
     * @returns {boolean} True if the `signIn` has been called.
     */
    public static wasSignInCalled(): boolean {
        if (SPAUtils.hasErrorInURL() || SPAUtils.hasAuthSearchParamsInURL()) {
            if (!this.isSilentStatePresentInURL()) {
                return true;
            }
        }

        return false;
    }

    public static wasSilentSignInCalled(): boolean {
        const silentSignIsInitialized = sessionStorage.getItem(INITIALIZED_SILENT_SIGN_IN);
        const isSilentSignInInitialized = silentSignIsInitialized ? JSON.parse(silentSignIsInitialized) : null;

        return Boolean(isSilentSignInInitialized);
    }

    public static async isSignOutSuccessful(): Promise<boolean> {
        if (AsgardeoAuthClient.isSignOutSuccessful(window.location.href)) {
            const newUrl = window.location.href.split("?")[0];
            history.pushState({}, document.title, newUrl);

            await AsgardeoAuthClient.clearUserSessionData();

            return true;
        }
        return false;
    }

    public static didSignOutFail(): boolean | SignOutError {
        if (AsgardeoAuthClient.didSignOutFail(window.location.href)) {
            const url: URL = new URL(window.location.href);
            const error: string | null = url.searchParams.get(ERROR);
            const description: string | null = url.searchParams.get(ERROR_DESCRIPTION);
            const newUrl = window.location.href.split("?")[0];
            history.pushState({}, document.title, newUrl);

            return {
                description: description ?? "",
                error: error ?? ""
            };
        }

        return false;
    }

    /**
     * Checks if the URL the user agent is redirected to after an authorization request has the state parameter.
     *
     * @returns {boolean} True if there is a session-check state or a silent sign-in state.
     */
    public static isSilentStatePresentInURL(): boolean {
        const state = new URL(window.location.href).searchParams.get("state");

        return state?.includes(SILENT_SIGN_IN_STATE) ?? false;
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

        return AUTH_CODE_REGEXP.test(params);
    }

    /**
     * Util function to check if the URL contains an error.
     *
     * @param url - URL to be checked.
     *
     * @returns {boolean} - True if the URL contains an error.
     */
    public static hasErrorInURL(url: string = window.location.href): boolean {
        const urlObject: URL = new URL(url);
        return (
            !!urlObject.searchParams.get(ERROR) && urlObject.searchParams.get(STATE_QUERY) !== SIGN_OUT_SUCCESS_PARAM
        );
    }

    /**
     * Checks if a prompt none can be sent by checking if a request has already been sent.
     *
     * @since 0.2.3
     *
     * @returns {boolean} - True if a prompt none request has not been sent.
     */
    public static canSendPromptNoneRequest(): boolean {
        const promptNoneRequestSentRaw = sessionStorage.getItem(PROMPT_NONE_REQUEST_SENT);
        const promptNoneRequestSent = promptNoneRequestSentRaw ? JSON.parse(promptNoneRequestSentRaw) : null;

        return !promptNoneRequestSent;
    }

    /**
     * Sets the status of prompt none request.
     *
     * @since 0.2.3
     *
     * @param canSend {boolean} - True if a prompt none request can be sent.
     */
    public static setPromptNoneRequestSent(canSend: boolean): void {
        sessionStorage.setItem(PROMPT_NONE_REQUEST_SENT, JSON.stringify(canSend));
    }

    /**
     * Waits for a specified amount of time to give the user agent enough time to redirect.
     *
     * @param time {number} - Time in seconds.
     */
    public static async waitTillPageRedirect(time?: number): Promise<void> {
        const timeToWait = time ?? 3000;

        await new Promise((resolve) => setTimeout(resolve, timeToWait * 1000));
    }
}

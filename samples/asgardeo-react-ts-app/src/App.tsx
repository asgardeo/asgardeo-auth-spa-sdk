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

import React, {
  FunctionComponent,
  ReactElement,
  useEffect,
  useState,
} from "react";
import "./App.css";
import ReactLogo from "./images/react-logo.png";
import JavascriptLogo from "./images/js-logo.png";
import FooterLogo from "./images/footer.png";
import { default as authConfig } from "./config.json";
import {
  AsgardeoSPAClient,
  AuthClientConfig,
  Hooks,
  BasicUserInfo,
  Config,
} from "@asgardeo/auth-spa";

/**
 * SDK Client instance.
 * @type {AsgardeoSPAClient}
 */
const auth: AsgardeoSPAClient = AsgardeoSPAClient.getInstance();

const authConfigx = {
  signInRedirectURL: "https://localhost:3000/signin",
  signOutRedirectURL: "https://localhost:3000/login",
  clientID: "GEjPOPRsoMMlNrDuO8fqCBL4mS8a",
  serverOrigin: "https://id.dv.choreo.dev:443",
  clientHost: "https://localhost:3000",
  enablePKCE: true,
  storage: "sessionStorage",
  checkSessionInterval: -1,
  disableTrySignInSilently: true,
  resourceServerURLs: [
    "https://km.preview-dv.choreo.dev",
    "https://apim.preview-dv.choreo.dev",
    "https://apim.preview-st.choreo.dev",
    "https://id.dv.choreo.dev",
    "https://consolev2.preview-dv.choreo.dev",
    "https://app.preview-dv.choreo.dev",
    "https://appv2.preview-dv.choreo.dev",
    "https://app.preview-st.choreo.dev",
    "https://appv2.preview-st.choreo.dev",
    "https://choreocontrolplane.preview-dv.choreo.dev/insights/1.0.0/query-api",
    "https://choreocontrolplane.preview-dv.choreo.dev/insightsalert/1.0.0/",
    "https://localhost:3000",
    "https://run.mocky.io",
  ],
};

const TOKEN_EXCHANGE_CONFIG = {
  tokenEndpoint: "https://apim.preview-dv.choreo.dev:443/oauth2/token",
  attachToken: false,
  data: {
    client_id: "Wxqy0liCfLBsdpXOhkcxZz6uLPka",
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
    requested_token_type: "urn:ietf:params:oauth:token-type:jwt",
    scope:
      "apim:api_manage apim:subscription_manage apim:tier_manage apim:admin apim:publisher_settings",
    subject_token: "{{token}}",
  },
  id: "apim-token-exchange",
  returnResponse: true,
  returnsSession: true,
  signInRequired: true,
};
/**
 * Main App component.
 *
 * @return {React.ReactElement}
 */
export const App: FunctionComponent<{}> = (): ReactElement => {
  const [authenticatedUser, setAuthenticatedUser] =
    useState<BasicUserInfo>(undefined);
  const [isAuth, setIsAuth] = useState<boolean>(false);

  /**
   * Initialize the SDK & register Sign in and Sign out hooks.
   */
  useEffect(() => {
    // Initialize the client with the config object.
    auth.initialize(authConfigx as AuthClientConfig<Config>);

    auth.on(
      Hooks.CustomGrant,
      (_aa) => {
        debugger;
      },
      "foo"
    );

    auth.on(Hooks.SignIn, (response: BasicUserInfo) => {
      debugger;
      auth.requestCustomGrant(TOKEN_EXCHANGE_CONFIG);

      setIsAuth(true);
      setAuthenticatedUser(response);
    });

    auth.on(Hooks.SignOut, () => {
      setIsAuth(false);
    });

    auth.signIn({
      fidp: "google-choreo",
    });
  }, []);

  /**
   * Check if the page redirected by the sign-in method with authorization code,
   * if it is recall sing-in method to continue the sign-in flow
   */
  useEffect(() => {
    if (isAuth) {
      return;
    }

    auth.isAuthenticated().then(async (response) => {
      if (response) {
        const userInfo = await auth.getBasicUserInfo();
        setAuthenticatedUser({
          ...userInfo,
        });

        setIsAuth(true);
      }
    });
  }, [authenticatedUser, isAuth]);

  /**
   * Handles login button click event.
   */
  const handleLogin = (): void => {
    auth.signIn();
  };

  /**
   * Handles logout button click event.
   */
  const handleLogout = async (): Promise<any> => {
    await auth.httpRequest({
      url: "https://run.mocky.io/v3/9641a9d1-55dd-4cb7-b6dc-e2d2a9204074",
      method: "GET",
    });
  };

  return (
    <>
      {isAuth && authenticatedUser ? (
        <>
          <div className="header-title">
            <h1>Javascript-based React SPA Authentication Sample</h1>
          </div>
          <div className="content">
            <h3>
              Below are the basic details retrieved from the server on a
              successful login.
            </h3>
            <div>
              <ul className="details">
                {authenticatedUser.displayName && (
                  <li>
                    <b>Name:</b> {authenticatedUser.displayName}
                  </li>
                )}
                {authenticatedUser.username && (
                  <li>
                    <b>Username:</b> {authenticatedUser.username}
                  </li>
                )}
                {authenticatedUser.email && authenticatedUser.email !== "null" && (
                  <li>
                    <b>Email:</b> {authenticatedUser.email}
                  </li>
                )}
              </ul>
            </div>
            <button className="btn primary" onClick={() => handleLogout()}>
              API Call
            </button>
          </div>
        </>
      ) : (
        <div className="header-title">
          <h1>Authenticating ....</h1>
        </div>
      )}
    </>
  );
};

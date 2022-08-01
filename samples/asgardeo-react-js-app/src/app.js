/**
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import ReactJson from "react-json-view";
import "./app.css";
import REACT_LOGO from "./images/react-logo.png";
import JS_LOGO from "./images/js-logo.png";
import FOOTER_LOGOS from "./images/footer.png";
// Import Asgardeo Auth SPA JS SDK
import { Hooks, AsgardeoSPAClient } from "@asgardeo/auth-spa";
import { ReactNotifications } from "react-notifications-component";
import { Store } from "react-notifications-component";
import "react-notifications-component/dist/theme.css";
import * as authConfig from "./config.json";

const authClient = AsgardeoSPAClient.getInstance();
const API_ENDPOINT = `${authConfig?.default?.baseUrl}/oauth2/userinfo`;

const App = () => {

    const [ authenticateState, setAuthenticateState ] = useState({});
    const [ isAuth, setIsAuth ] = useState(false);
    const [ isLoading, setIsLoading ] = useState(true);
    const [ hasLogoutFailureError, setHasLogoutFailureError ] = useState();
    const [ hasAuthRequiredError, setHasAuthRequiredError ] = useState();
    const [ apiResponse, setApiResponse ] = useState(null);

    const urlParams = new URLSearchParams(window.location.search);
    const stateParam = urlParams.get('state');
    const errorDescParam = urlParams.get('error_description');

    useEffect(() => {
        if(stateParam && errorDescParam) {
            if(errorDescParam === "Authentication required") {
                setHasAuthRequiredError(true);
            } else if(errorDescParam === "End User denied the logout request") {
                setHasLogoutFailureError(true);
            }
        }
    }, [stateParam, errorDescParam]);


    const parseIdToken = (idToken) => {
        if (!idToken) {
            return;
        }

        if (typeof idToken !== "string") {
            idToken = JSON.stringify(idToken);
        }

        const idTokenSplit = idToken.split(".");
        let idTokenObject = {
            "encoded": [],
            "decoded": []
        };

        idTokenSplit.forEach((element) => {
            idTokenObject["encoded"].push(element);
        });

        idTokenObject["decoded"].push(JSON.parse(atob(idTokenObject.encoded[0])));
        idTokenObject[ "decoded" ].push(JSON.parse(atob(idTokenObject.encoded[ 1 ])));

        const sub = idTokenObject[ "decoded" ][ 1 ] && idTokenObject[ "decoded" ][ 1 ]?.sub?.split("/");

        if (sub.length >= 2) {
            sub.shift();
            idTokenObject[ "decoded" ][ 1 ].sub = sub.join("/");
        }

        const groups = [];
        idTokenObject[ "decoded" ][ 1 ] && typeof idTokenObject[ "decoded" ][ 1 ]?.groups === "string" &&
            groups.push(idTokenObject[ "decoded" ][ 1 ]?.groups);

        idTokenObject[ "decoded" ][ 1 ] && typeof idTokenObject[ "decoded" ][ 1 ]?.groups !== "string" &&
            idTokenObject[ "decoded" ][ 1 ]?.groups?.forEach((group) => {
                const groupArrays = group.split("/");

                if (groupArrays.length >= 2) {
                    groupArrays.shift();
                    groups.push(groupArrays.join("/"));
                } else {
                    groups.push(group);
                }
            });

        if (idTokenObject[ "decoded" ][ 1 ]?.groups) {
            idTokenObject[ "decoded" ][ 1 ].groups = groups;
        }

        return idTokenObject;
    };

    useEffect(() => {
        authClient.on(Hooks.SignIn, async (response) => {
            const username = response?.username?.split("/");

            if (username && username.length >= 2) {
                username.shift();
                response.username = username.join("/");
            }

            authClient.getIDToken().then((idToken) => {
                sessionStorage.setItem("authenticateResponse", JSON.stringify(response));

                setAuthenticateState({
                    ...authenticateState,
                    authenticateResponse: response,
                    idToken: parseIdToken(idToken)
                });

                setIsAuth(true);
                setIsLoading(false);
            });

            try {
                const apiResponse = await performAPIRequest();
                apiResponse && setApiResponse(apiResponse);
            } catch (error) {
                Store.addNotification({
                    title: "Error!",
                    message: "Invoking the API has failed",
                    type: "danger",
                    insert: "top",
                    container: "top-right",
                    animationIn: ["animate__animated", "animate__fadeIn"],
                    animationOut: ["animate__animated", "animate__fadeOut"],
                    dismiss: {
                      duration: 4000,
                      onScreen: true
                    }
                });
            }
        });

        authClient.on(Hooks.SignOut, () => {
            setIsAuth(false);
            setIsLoading(false);
            setHasLogoutFailureError(false);
        });
    }, [authClient.on]);

    const handleLogin = () => {
        setHasLogoutFailureError(false);
        setIsLoading(true);
        authClient.signIn();
    };

    const handleLogout = () => {
        authClient.signOut();
    };

    const performAPIRequest = async () => {
        return await authClient.httpRequest({
            url: API_ENDPOINT
        });
     }

    useEffect(() => {

        authClient.initialize(authConfig.default);

        authClient.signIn({ callOnlyOnRedirect: true });

        authClient.isAuthenticated().then((isAuthenticated) => {
            if (isAuthenticated) {
                authClient.getIDToken().then((idToken) => {
                    setAuthenticateState({
                        ...authenticateState,
                        authenticateResponse: JSON.parse(sessionStorage.getItem("authenticateResponse")),
                        idToken: parseIdToken(idToken)
                    });

                    setIsAuth(true);
                });
            }

            setIsLoading(false);
        });

    }, []);

    return (
        <>
            <div className="container">
                { authConfig.default.clientID === "" ?
                    <div className="content">
                        <h2>You need to update the Client ID to proceed.</h2>
                        <p>Please open "src/config.json" file using an editor, and update the <code>clientID</code> value with the registered application's client ID.</p>
                        <p>Visit repo <a href="https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/samples/asgardeo-react-js-app">README</a> for more details.</p>
                    </div>
                :
                   <>
                        <div className="header-title">
                            <h1>
                                JavaScript Based React SPA Authentication Sample
                            </h1>
                        </div>
                        <div className="content">
                            { isLoading ?
                                <div>Loading ...</div>
                            :   hasLogoutFailureError ?
                                    <div className="ui visible negative message">
                                        <h3 className="mt-4 b">End User denied the logout request</h3>
                                        <p className="my-4">
                                            <a className="link-button pointer" role="button" onClick={handleLogin}>
                                                Try Log in again
                                            </a>
                                            &nbsp;or&nbsp;
                                            <a onClick={handleLogout} className="link-button pointer" role="button">
                                                Log out from the application.
                                            </a>
                                        </p>
                                    </div>
                            :   hasAuthRequiredError ?
                                    <>
                                        <div class="segment-form">
                                            <div class="ui visible negative message">
                                                <div class="header"><b>Authentication Error!</b></div>
                                                <p>Please check application configuration and try login again!.</p>
                                            </div>
                                        </div>
                                        <button className="btn primary" onClick={ handleLogin }>Login</button>
                                    </>
                            :   <> 
                                    { isAuth ?
                                        <>
                                            {
                                                apiResponse ? (
                                                    <>
                                                        <h2>API Response</h2>
                                                        <div className="json">
                                                            {/* @ts-ignore */}
                                                            <ReactJson
                                                                src={ apiResponse["data"] }
                                                                name={ null }
                                                                enableClipboard={ false }
                                                                displayObjectSize={ false }
                                                                displayDataTypes={ false }
                                                                iconStyle="square"
                                                                theme="monokai"
                                                            />
                                                        </div>
                                                    </>
                                                ) : null
                                            }
                                            <h2>Authentication response derived by the Asgardeo Auth SPA JS SDK</h2>
                                            <div className="json">
                                                <ReactJson
                                                    src={ authenticateState.authenticateResponse }
                                                    name={ null }
                                                    enableClipboard={ false }
                                                    displayObjectSize={ false }
                                                    displayDataTypes={ false }
                                                    iconStyle="square"
                                                    theme="monokai"
                                                />
                                            </div>

                                            <h2 className="mb-0 mt-4">ID token</h2>

                                            <div className="row">
                                                { authenticateState.idToken &&
                                                    <>
                                                        <div className="column">
                                                            <h5><b>Encoded</b></h5>
                                                            <div className="code">
                                                                <code>
                                                                    <span className="id-token-0">{ authenticateState.idToken.encoded[0] }</span>.
                                                                    <span className="id-token-1">{ authenticateState.idToken.encoded[1] }</span>.
                                                                    <span className="id-token-2">{ authenticateState.idToken.encoded[2] }</span>
                                                                </code>
                                                            </div>
                                                        </div>

                                                        <div className="column">
                                                            <div className="json">
                                                                <h5><b>Decoded:</b> Header</h5>
                                                                <ReactJson
                                                                    src={ authenticateState.idToken.decoded[0] }
                                                                    name={ null }
                                                                    enableClipboard={ false }
                                                                    displayObjectSize={ false }
                                                                    displayDataTypes={ false }
                                                                    iconStyle="square"
                                                                    theme="monokai"
                                                                />
                                                            </div>

                                                            <div className="json">
                                                                <h5><b>Decoded:</b> Payload</h5>
                                                                <ReactJson
                                                                    src={ authenticateState.idToken.decoded[1] }
                                                                    name={ null }
                                                                    enableClipboard={ false }
                                                                    displayObjectSize={ false }
                                                                    displayDataTypes={ false }
                                                                    iconStyle="square"
                                                                    theme="monokai"
                                                                />
                                                            </div>

                                                            <div className="json">
                                                                <h5>Signature</h5>
                                                                <div className="code">
                                                                    <code>
                                                                        HMACSHA256(
                                                                            <br />
                                                                            &nbsp;&nbsp;<span className="id-token-0">base64UrlEncode(
                                                                                <span className="id-token-1">header</span>)</span> + "." + <br />
                                                                            &nbsp;&nbsp;<span className="id-token-0">base64UrlEncode(
                                                                                <span className="id-token-1">payload</span>)</span>,&nbsp;
                                                                            <span className="id-token-1">your-256-bit-secret</span> <br />
                                                                        );
                                                                    </code>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </>
                                                }
                                            </div>

                                            <button className="btn primary mt-4" onClick={ handleLogout }>Logout</button>

                                        </>
                                    :
                                        <>

                                            <div className="home-image">
                                                <img src={ JS_LOGO } className="js-logo-image logo" />
                                                <span className="logo-plus">+</span>
                                                <img src={ REACT_LOGO } className="react-logo-image logo" />
                                            </div>
                                            <h3>
                                                Sample demo to showcase authentication for a Single Page
                                                Application <br />
                                                via the OpenID Connect Authorization Code flow, <br />
                                                which is integrated using the { " " }
                                                <a href="https://github.com/asgardeo/asgardeo-auth-spa-sdk"
                                                   target="_blank">
                                                    Asgardeo Auth SPA JS SDK</a>.
                                            </h3>
                                            <button className="btn primary" onClick={ handleLogin }>Login</button>

                                        </>
                                    }
                                </>
                            }
                        </div>
                    </>
                }
            </div>

            <img src={ FOOTER_LOGOS } className="footer-image" />
        </>
    );

}

const AppWrapper = () => {
    return (
        <>
            <ReactNotifications />
            <App />
        </>
    )
};

const root = createRoot(document.getElementById("root"));
root.render(<AppWrapper />);

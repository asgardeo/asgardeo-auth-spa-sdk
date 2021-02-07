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
import * as ReactDOM from "react-dom";
import ReactJson from "react-json-view";
import "./app.css";
import PRODUCT_LOGOS from "./images/asgardeo-logo.png";
import REACT_LOGO from "./images/react-logo.png";
import JS_LOGO from "./images/js-logo.png";
import FOOTER_LOGOS from "./images/footer.png";
// Import Asgardeo Auth SPA JS SDK
import { Hooks, AsgardeoSPAClient } from "@asgardeo/auth-spa";
import * as authConfig from "./config.json";

const authClient = AsgardeoSPAClient.getInstance();

const App = () => {

    const [ authenticateState, setAuthenticateState ] = useState({});
    const [ isAuth, setIsAuth ] = useState(false);
    const [ isLoading, setIsLoading ] = useState(true);

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
        idTokenObject["decoded"].push(JSON.parse(atob(idTokenObject.encoded[1])));

        return idTokenObject;
    };

    authClient.on(Hooks.SignIn, (response) => {
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
    });

    authClient.on(Hooks.SignOut, () => {
        setIsAuth(false);
        setIsLoading(false);
    });

    const handleLogin = () => {
        authClient.signIn();
    };

    const handleLogout = () => {
        authClient.signOut();
    };

    useEffect(() => {

        authClient.initialize(authConfig.default);

        // Check if the page redirected by the sign-in method with authorization code, if it is recall sign-in method to
        // continue the sign-in flow
        if ( JSON.parse(sessionStorage.getItem("initialized-sign-in")) ) {
            authClient.signIn({ callOnlyOnRedirect: true });
        }
        else {
            authClient.isAuthenticated().then((response) => {
                if (response) {
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
        }

    }, []);

    return (
        <>
            <img src={ PRODUCT_LOGOS } className="logo-image" />
            <div className="container">
                { authConfig.default.clientID === "" ?
                    <div className="content">
                        <h2>You need to update the Client ID to proceed.</h2>
                        <p>Please open "src/config.json" file using an editor, and update the <code>clientID</code> value with the registered application's client ID.</p>
                        <p>Visit repo <a href="https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/samples/react-js-app">README</a> for more details.</p>
                    </div>
                :
                   <>
                        <div className="header-title">
                            <h1>
                                JavaScript Based React SPA Authentication Sample <br /> (OIDC - Authorization Code Grant)
                            </h1>
                        </div>
                        <div className="content">
                            { isLoading ?
                                <div>Loading ...</div>
                            :
                                <>
                                    { isAuth ?
                                        <>
                                            <h2>Authentication response</h2>
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
                                                                <h5><b>Signature:</b></h5>
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
                                                Sample demo to showcase how to authenticate a simple client side application using <br/>
                                                <b>Asgardeo</b> with the <a href="https://github.com/asgardeo/asgardeo-auth-spa-sdk" target="_blank">Asgardeo Auth SPA JS SDK</a>
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

ReactDOM.render( (<App />), document.getElementById("root") );

<!--
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
 -->

<%
    session.setAttribute("authCode",request.getParameter("code"));
    session.setAttribute("sessionState", request.getParameter("session_state"));
%>

<html>
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="referrer" content="no-referrer" />

        <title>Asgardeo - HTML Javascript Authentication Sample Using Asgardeo OIDC JS SDK</title>

        <link href="app.css" rel="stylesheet" type="text/css" />
    </head>
    <body>
        <div class="container">
            <div id="missing-config" style="display: none">
                <div class="content">
                    <h2>You need to update the Client ID to proceed.</h2>
                    <p>
                        Please open the <b>index.html</b> file using an text editor, and update the
                        <code>clientID</code> value in the <code>authConfig</code> object.
                    </p>
                    <p>
                        Visit repo
                        <a
                            href="https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/samples/asgardeo-java-webapp"
                            >README</a
                        >
                        for more details.
                    </p>
                </div>
            </div>

            <div id="logged-in-view" style="display: none">
                <div class="header-title">
                    <h1>
                        Javascript-based Authentication Sample
                    </h1>
                </div>
                <div class="content">
                    <h3>Below are the basic details retrieved from the server on a successful login.</h3>
                    <div>
                        <ul class="details">
                            <li id="display-name-item"><b>Name:</b> <span id="text-display-name"></span></li>
                            <li id="username-item"><b>Username:</b> <span id="text-username"></span></li>
                            <li id="email-item"><b>Email:</b> <span id="text-email"></span></li>
                        </ul>
                    </div>
                    <button class="btn primary" onClick="handleLogout()">Logout</button>
                </div>
            </div>

            <div id="logged-out-view" style="display: none">
                <div class="header-title">
                    <h1>
                        Javascript-based Authentication Sample
                    </h1>
                </div>
                <div class="content">
                    <img src="images/home.png" class="home-image" />
                    <h3>
                        Sample demo to showcase authentication for a Single Page Application <br />
                        via the OpenID Connect Authorization Code flow, <br />
                        which is integrated using the
                        <a href="https://github.com/asgardeo/asgardeo-auth-spa-sdk" target="_blank" rel="noreferrer"
                            >Asgardeo Auth SPA SDK</a>.
                    </h3>
                    <button class="btn primary" onClick="handleLogin()">Login</button>
                </div>
            </div>
        </div>

        <img src="images/footer.png" class="footer-image" />

        <script src="https://cdn.jsdelivr.net/npm/axios@0.20.0/dist/axios.min.js"></script>
        <!-- Add Asgardeo Auth SPA SDK -->
        <script
            type="application/javascript"
            src="https://unpkg.com/@asgardeo/auth-spa@latest/dist/asgardeo-spa.production.min.js"
        ></script>

        <!-- Asgardeo SDK Init Config -->
        <script>
            const authConfig = {
                // ClientID generated for the application
                clientID: "",
                // After login callback URL - We have use app root as this is a SPA
                // (Add it in application OIDC settings "Callback Url")
                signInRedirectURL: origin,
                // Asgardeo base url - Contains domain with the tenant
                baseUrl: "",
                responseMode: "form_post",
                scope: ["profile"]
            };
        </script>

        <script type="application/javascript" src="app.js"></script>
    </body>
</html>

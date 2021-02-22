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

/**
 * SDK Client instance.
 */
var authClient = AsgardeoAuth.AsgardeoSPAClient.getInstance();

/**
 * Initialize the client with the config object. Check `index.html` for the config object.
 */
authClient.initialize(authConfig);

/**
 * Authenticated State.
 */
var state = {
    isAuth: false,
    authenticateResponse: null,
    idToken: null
};

/**
 * Pass the callback function to be called after sign in using the `sign-in` hook.
 */
authClient.on("sign-in", function (response) {
    const username = response?.username?.split("/");

    if (username.length >= 2) {
        username.shift();
        response.username = username.join("/");
    }

    setAuthenticatedState(response);
});

/**
 * Pass the callback function to be called after sign out using the `sign-out` hook.
 */
authClient.on("sign-out", function (response) {
    state.isAuth = false;
    updateView();
});

/**
 * Method to split ID token.
 */
function parseIdToken(idToken) {
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

    idTokenSplit.forEach(function(element) {
        idTokenObject["encoded"].push(element);
    });

    idTokenObject["decoded"].push(JSON.parse(atob(idTokenObject.encoded[0])));
    idTokenObject["decoded"].push(JSON.parse(atob(idTokenObject.encoded[1])));

    const sub = idTokenObject[ "decoded" ][ 1 ] && idTokenObject[ "decoded" ][ 1 ]?.sub?.split("/");

    if (sub.length >= 2) {
        sub.shift();
        idTokenObject[ "decoded" ][ 1 ].sub = sub.join("/");
    }

    const groups = [];
    idTokenObject[ "decoded" ][ 1 ] && idTokenObject[ "decoded" ][ 1 ]?.groups?.forEach((group) => {
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
}

/**
 * Updates the view after a sign-in or sign-out.
 */
function updateView() {
    var authenticationResponseViewBox = document.getElementById("authentication-response");
    var idTokenHeaderViewBox = document.getElementById("id-token-header");
    var idTokenPayloadViewBox = document.getElementById("id-token-payload");
    var loggedInView = document.getElementById("logged-in-view");
    var loggedOutView = document.getElementById("logged-out-view");

    if (state.isAuth) {

        var formattedAuthenticateResponse = new JSONFormatter(state.authenticateResponse, 1, { theme: "dark" });
        var formattedDecodedIdTokenHeader = new JSONFormatter(state.idToken.decoded[0], 1, { theme: "dark" });
        var formattedDecodedIdTokenPayload = new JSONFormatter(state.idToken.decoded[1], 1, { theme: "dark" });

        authenticationResponseViewBox.innerHTML = "";
        idTokenHeaderViewBox.innerHTML = "";
        idTokenPayloadViewBox.innerHTML = "";

        authenticationResponseViewBox.appendChild(formattedAuthenticateResponse.render());
        idTokenHeaderViewBox.appendChild(formattedDecodedIdTokenHeader.render());
        idTokenPayloadViewBox.appendChild(formattedDecodedIdTokenPayload.render());

        document.getElementById("id-token-0").innerHTML = state.idToken.encoded[0];
        document.getElementById("id-token-1").innerHTML = state.idToken.encoded[1];
        document.getElementById("id-token-2").innerHTML = state.idToken.encoded[2];

        loggedInView.style.display = "block";
        loggedOutView.style.display = "none";
    } else {
        loggedInView.style.display = "none";
        loggedOutView.style.display = "block";
    }
}

/**
 * Sets the authenticated user's information & auth state.
 */
function setAuthenticatedState(response) {
    authClient.getIDToken().then((idToken) => {
        state.authenticateResponse = response;
        state.idToken = parseIdToken(idToken);

        sessionStorage.setItem("authenticateResponse", JSON.stringify(response));

        state.isAuth = true;

        updateView();
    });
}

/**
 * Handles login button click event.
 */
function handleLogin() {
    authClient.signIn();
}

/**
 * Handles logout button click event.
 */
function handleLogout() {
    authClient.signOut();
}

if (authConfig.clientID === "") {
    document.getElementById("missing-config").style.display = "block";
} else {
    // Check if the page redirected by the sign-in method with authorization code, if it is recall sing-in method to
    // continue the sign-in flow
    if (JSON.parse(sessionStorage.getItem("initialized-sign-in"))) {
        authClient.signIn({ callOnlyOnRedirect: true });
        updateView();
    } else {
        authClient.isAuthenticated().then(function(isAuthenticated) {
            if (isAuthenticated) {
                authClient.getIDToken().then(function(idToken) {
                    state.authenticateResponse = JSON.parse(sessionStorage.getItem("authenticateResponse"));
                    state.idToken = parseIdToken(idToken);
                    state.isAuth = true;

                    updateView();
                });
            }

            updateView();
        });
    }
}

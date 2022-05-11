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

let isLoading = true;

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

let hasLogoutFailureError = false;
let hasAuthRequiredError = false;

const urlParams = new URLSearchParams(window.location.search);
const stateParam = urlParams.get('state');
const errorDescParam = urlParams.get('error_description');

if(stateParam && errorDescParam) {
    if(errorDescParam === "Authentication required") {
        hasAuthRequiredError = true;
    } else if(errorDescParam === "End User denied the logout request") {
        hasLogoutFailureError = true;
    }
}
/**
 * Pass the callback function to be called after sign in using the `sign-in` hook.
 */
authClient.on("sign-in", function (response) {
    var username = response?.username?.split("/");

    if (username?.length >= 2) {
        username.shift();
        response.username = username.join("/");
    }

    updateView();
    setAuthenticatedState(response);
});

/**
 * Pass the callback function to be called after sign out using the `sign-out` hook.
 */
authClient.on("sign-out", function (response) {
    state.isAuth = false;
    hasLogoutFailureError = false;
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

    var sub = idTokenObject[ "decoded" ][ 1 ] && idTokenObject[ "decoded" ][ 1 ]?.sub?.split("/");

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
    var userDeniedLogoutView = document.getElementById("user-denied-logout-view");
    var errorAuthenticatingView = document.getElementById("error-authenticating-view");

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
        userDeniedLogoutView.style.display = "none";
        errorAuthenticatingView.style.display = "none";
    } else if(hasLogoutFailureError) {
        loggedInView.style.display = "none";
        loggedOutView.style.display = "none";
        userDeniedLogoutView.style.display = "block";
        errorAuthenticatingView.style.display = "none";
    } else if(hasAuthRequiredError) {
        loggedInView.style.display = "none";
        loggedOutView.style.display = "none";
        userDeniedLogoutView.style.display = "none";
        errorAuthenticatingView.style.display = "block";
    } else {
        loggedInView.style.display = "none";
        userDeniedLogoutView.style.display = "none";
        errorAuthenticatingView.style.display = "none";

        if (!isLoading) {
            loggedOutView.style.display = "block";
        }
    }

    if (!isLoading) {
        document.getElementById("loading").style.display = "none";
    }

    document.getElementById("error").style.display = "none";
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
    hasLogoutFailureError = false;
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
    authClient.signIn({ callOnlyOnRedirect: true }).catch(() => {
        document.getElementById("error").style.display = "block";
    }).finally(() => {
        isLoading = false;
        updateView();
    });

    if(!hasLogoutFailureError) {
        authClient.isAuthenticated().then(function (isAuthenticated) {
            if (isAuthenticated) {
                authClient.getIDToken().then(function (idToken) {
                    state.authenticateResponse = JSON.parse(sessionStorage.getItem("authenticateResponse"));
                    state.idToken = parseIdToken(idToken);
                    state.isAuth = true;
    
                    updateView();
                });
            } else {
                updateView();
            }
        });
    }
}

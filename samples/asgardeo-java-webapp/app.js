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
var auth = AsgardeoAuth.AsgardeoSPAClient.getInstance();

/**
 * Authenticated State.
 */
var state = {
    isAuth: false,
    displayName: "",
    email: "",
    username: ""
};

/**
 * Initializes the SDK.
 */
function initialize() {
    // Initialize the client with the config object. Check `index.html` for the config object.
    auth.initialize(authConfig);

    //Pass the callback function to be called after signing in using the `sign-in` hook
    auth.on("sign-in", function (response) {
        setAuthenticatedState(response);
        updateView();
    });
}

/**
 * Updates the view after a login or logout.
 */
function updateView() {
    if (state.isAuth) {
        document.getElementById("text-display-name").innerHTML = state.displayName;
        document.getElementById("text-username").innerHTML = state.username;
        document.getElementById("text-email").innerHTML = state.email;

        if (!state.displayName) {
            document.getElementById("display-name-item").style.display = "none";
        }

        if (!state.email) {
            document.getElementById("email-item").style.display = "none";
        }

        if (!state.username) {
            document.getElementById("user-name-item").style.display = "none";
        }

        document.getElementById("logged-in-view").style.display = "block";
        document.getElementById("logged-out-view").style.display = "none";
    } else {
        document.getElementById("logged-in-view").style.display = "none";
        document.getElementById("logged-out-view").style.display = "block";
    }
}

/**
 * Sets the authenticated user's information & auth state.
 */
function setAuthenticatedState(response) {
    state.displayName = response.displayName;
    state.email =
        response.email !== null && response.email !== "null" && response.email.length && response.email.length > 0
            ? response.email[ 0 ]
            : "";
    state.username = response.username;
    state.isAuth = true;
}

/**
 * Handles login button click event.
 */
function handleLogin() {
    auth.signIn();
}

/**
 * Handles logout button click event.
 */
function handleLogout() {
    auth.signOut();
}

// Initialize the SDK.
initialize();

auth.on("sign-out", function () {
    state.isAuth = false;
    updateView();
});

if (authConfig.clientID === "") {
    document.getElementById("missing-config").style.display = "block";
} else {
    axios.get("asgardeo-java-webapp/auth").then((response) => {
        auth.signIn({ callOnlyOnRedirect: true }, response.data.authCode, response.data.sessionState);
    });

    auth.isAuthenticated().then((response) => {
        if (response) {
            auth.getBasicUserInfo().then((response) => {
                setAuthenticatedState(response);
                updateView();
            });
        } else {
            updateView();
        }
    });
}

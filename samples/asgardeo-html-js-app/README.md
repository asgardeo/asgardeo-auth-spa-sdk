# HTML Javascript Sample Application using Asgardeo Auth SPA SDK

## Getting Started

### Register an Application

Follow the instructions in the [Try Out the Sample Apps](../../README.md#try-out-the-sample-apps) section to register an application.

Make sure to add `https://localhost:3000` as a Redirect URL and also add it under allowed origins.

### Configuring the Sample

1. Update the `authConfig` object in `index.html` with your registered app details.

Note: You will only have to paste in the `client ID` generated for the application you registered.

Read more about the SDK configurations [here](../../README.md#initialize) .

```js
const authConfig = {
    // ClientID generated for the application
    clientID: "<ADD_CLIENT_ID_HERE>",
    // After login callback URL - We have to use the app root as this is a SPA
    // (Add it in application OIDC settings "Callback Url")
    signInRedirectURL: origin,
    // Asgardeo URL
    baseUrl: "<ADD_BASE_URL_HERE>",
};
```

### Run the Application

Note: If you are deploying and testing out this sample in your own server environment, just adding the static files would be enough.
The following steps demonstrates the usage of a 3rd party module to serve up the static content.

### Install Dependencies

The sample is using [http-server](https://www.npmjs.com/package/http-server) package to serve the static files.
You have to install it through npm.

```bash
npm install
```

### Starting the server

```bash
npm start
```

The app should open at `https://localhost:3000`. If the browser doesn't open the app and throws an invalid-certificate error, just type `thisisunsafe` to continue.

### Change the Application's Development Server Port

By default, the development server runs on port `3000`. Incase if you wish to change this to something else, follow the steps below.

1. Update the `PORT` in [.env](.env) file in the app root.
2. Update the `signInRedirectURL` & `signOutRedirectURL` in `authConfig` object in [index.html](./index.html).
3. Go to the Asgardeo Console and navigate to the protocol tab of your application:
    - Update the Authorized Redirect URL.
    - Update the Allowed Origins.

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](../../LICENSE)), You may not use this file except in compliance with the License.

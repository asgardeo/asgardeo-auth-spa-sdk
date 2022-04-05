/**
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com) All Rights Reserved.
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

require("dotenv").config();
const chalk = require("chalk");
const { exec } = require("child_process");
const { findPort } = require("dev-server-ports");

const HOST = "localhost";
const DESIRED_PORT = parseInt(process.env.PORT, 10) || 3000;
let resolvedPort = undefined;

const PORT_IN_USE_PROMPT = `${ chalk.blue("Be sure to update the following configurations if you proceed with the port change.") }

    1. Update the ${ chalk.bgBlack("PORT") } in ${ chalk.bgBlack(".env") } file in the app root.
    2. Update the signInRedirectURL & signOutRedirectURL in ${ chalk.bgBlack("authConfig") } object in ${ chalk.bgBlack("index.html") }.
    3. Go to the Asgardeo console and navigate to the protocol tab of your application:
        - Update the Authorized Redirect URL.
        - Update the Allowed Origins.
`;

findPort(DESIRED_PORT, HOST, false, {
  extensions: {
      BEFORE_getProcessTerminationMessage: () => {
        return PORT_IN_USE_PROMPT;
      }
  }
})
  .then((port) => {
    resolvedPort = port;
  })
  .catch((err) => {
    resolvedPort = DESIRED_PORT;
  })
  .finally(() => {
    const execution = exec(`node_modules/.bin/http-server -p ${ resolvedPort } -S -o -a localhost`);

    execution.stdout.pipe(process.stdout);
    execution.on("exit", () => {
      process.exit();
    });
  });

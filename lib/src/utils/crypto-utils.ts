/**
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import { Buffer } from "buffer";
import { AsgardeoAuthException, CryptoUtils, JWKInterface } from "@asgardeo/auth-js";
import base64url from "base64url";
import sha256 from "fast-sha256";
import { createLocalJWKSet, jwtVerify } from "jose";
import randombytes from "randombytes";

export class SPACryptoUtils implements CryptoUtils<Buffer | string>
{
    /**
     * Get URL encoded string.
     *
     * @returns {string} base 64 url encoded value.
     */
    public base64URLEncode(value: Buffer | string): string {
        return base64url.encode(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    public base64URLDecode(value: string): string {
        return base64url.decode(value).toString();
    }

    public hashSha256(data: string): string | Buffer {
        return Buffer.from(sha256(new TextEncoder().encode(data)));
    }

    public generateRandomBytes(length: number): string | Buffer {
        return randombytes(length);
    }

    public verifyJwt(
        idToken: string,
        jwk: Partial<JWKInterface>,
        algorithms: string[],
        clientID: string,
        issuer: string,
        subject: string,
        clockTolerance?: number,
        validateJwtIssuer?: boolean
    ): Promise<boolean> {
        const jwtVerifyOptions = {
            algorithms: algorithms,
            audience: clientID,
            clockTolerance: clockTolerance,
            subject: subject
        }

        if (validateJwtIssuer ?? true) {
            jwtVerifyOptions["issuer"] = issuer
        }

        return jwtVerify(
            idToken,
            createLocalJWKSet({
                keys: [jwk]
            }),
            jwtVerifyOptions
        ).then(() => {
            return Promise.resolve(true);
        }).catch((error) => {
            return Promise.reject(new AsgardeoAuthException(
                "SPA-CRYPTO-UTILS-VJ-IV01",
                error?.reason ?? JSON.stringify(error),
                `${error?.code} ${error?.claim}`
            ));
        });
    }
}

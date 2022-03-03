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
import { CryptoUtils, JWKInterface } from "@asgardeo/auth-js";
import base64url from "base64url";
import sha256 from "fast-sha256";
import { createLocalJWKSet, jwtVerify } from "jose";
import { FlattenedJWSInput, GetKeyFunction, JWSHeaderParameters } from "jose/dist/types/types";
import randombytes from "randombytes";

export class SPACryptoUtils
    implements CryptoUtils<Buffer | string, GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>>
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

    public parseJwk(key: Partial<JWKInterface>): Promise<GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>> {
        return Promise.resolve(
            createLocalJWKSet({
                keys: [ key ]
            })
        );
    }

    public verifyJwt(
        idToken: string,
        jwk: GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>,
        algorithms: string[],
        clientID: string,
        issuer: string,
        subject: string,
        clockTolerance?: number
    ): Promise<boolean> {
        return jwtVerify(idToken, jwk, {
            algorithms: algorithms,
            audience: clientID,
            clockTolerance: clockTolerance,
            issuer: issuer,
            subject: subject
        }).then(() => {
            return Promise.resolve(true);
        });
    }
}

import { Plugin, ResponseToolkit, Request, ResponseObject } from '@hapi/hapi';

declare module '@hapi/hapi' {
  interface ServerAuth {
    strategy(name: string, scheme: 'jwt', options?: hapiJwt.Options): void;
  }
}

declare namespace hapiJwt {
  /**
   * Key algorithms supported.
   */
  type SupportedAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512';
  type NoAlgorithm = 'none';

  /**
   * Key for HMAC and public algorithms.
   */
  interface StandardKey {
    /**
     * String or binary data that is used for shared secret.
     */
    key: string | Buffer;
    /**
     * Array of accepted algorithms
     */
    algorithms?: SupportedAlgorithm[];
    /**
     * String representing the key ID header.
     */
    kid?: string;
  }

  /**
   * JWKS key
   */
  interface JWKSKey {
    /**
     * String that defines your json web key set uri.
     */
    uri: string;
    /**
     * Boolean that determines if TLS flag indicating whether the client should reject a response from a server with invalid certificates. Default is true.
     */
    rejectUnauthorized?: boolean
    /**
     *Object containing the request headers to send to the uri.
     */
    header?: object;
    /**
     * Array of accepted algorithms.
     */
    algorithms?: SupportedAlgorithm[];
  }

  type Key = StandardKey | JWKSKey;

  interface VerifyOptions {
    /**
     * String or RegExp or array of strings or RegExp that matches the audience of the token. Set to boolean false to not verify aud.
     */
    aud: string | string[] | RegExp | RegExp[] | false;
    /**
     * String or array of strings that matches the issuer of the token. Set to boolean false to not verify iss.
     */
    iss: string | string[] | false;
    /**
     * String or array of strings that matches the subject of the token. Set to boolean false to not verify sub.
     */
    sub: string | string[] | false;
    /**
     * Boolean to determine if the "Not Before" NumericDate of the token should be validated. Default is true.
     */
    nbf?: boolean;
    /**
     * Boolean to determine if the "Expiration Time" NumericDate of the token should be validated. Default is true.
     */
    exp?: boolean;
    /**
     * Integer to determine the maximum age of the token in seconds. Default is 0.
     */
    maxAgeSec?: number;
    /**
     * Integer to adust exp and maxAgeSec to account for server time drift in seconds. Default is 0.
     */
    timeSkewSec?: number;
  }

  interface Artifacts {
    /**
     * The complete token that was sent.
     */
    token: string;
    /**
     * An object that contains decoded token.
     */
    decoded: {
      /**
       * An object that contain the header information.
       */
      header: {
        /**
         * The algorithm used to sign the token.
         */
        alg: string;
        /**
         *  The token type.
         */
        typ?: 'JWT';
      },
      /**
       *  An object containing the payload.
       */
      payload: object;
      /**
       *  The signature string of the token.
       */
      signature: string;
    };
    /**
     * An object that contains the token that was sent broken out by header, payload, and signature.
     */
    raw?: object;
    /**
     * An array of information about key(s) used for authentication.
     */
    keys?: StandardKey[];
  }

  interface ValidationResult {
    /**
     * Boolean that should be set to true if additional validation passed, otherwise false.
     */
    isValid: boolean;
    /**
     * Object passed back to the application in request.auth.credentials.
     */
    credentials?: object;
    /**
     * Will be used immediately as a takeover response. isValid and credentials are ignored if provided.
     */
    response?: ResponseObject;
  }

  /**
   * Options passed to `hapi.auth.strategy` when this plugin is used.
   */
  interface Options {
    /**
     * The key method to be used for jwt verification.
     */
    keys: string | string[] | Buffer | Key | Key[] | NoAlgorithm[] | ((param: any) => string);
    /**
     * Object to determine how key contents are verified beyond key signature. Set to false to do no verification.
     */
    verify: VerifyOptions | false;
    /**
     * String the represents the Authentication Scheme. Default is 'Bearer'.
     */
    httpAuthScheme?: string;
    /**
     * String passed directly to Boom.unauthorized if no custom err is thrown. Defaults to undefined.
     */
    unauthorizedAttributes?: string;
    /**
     * Function that allows additional validation based on the decoded payload and to put specific credentials in the request object. Can be set to false if no additional validation is needed.
     *
     * @param artifacts an object that contains information from the token.
     * @param request the hapi request object of the request which is being authenticated.
     * @param h the response toolkit.
     */
    validate: ((artifacts: Artifacts, request: Request, h: ResponseToolkit) => Promise<ValidationResult> | never) | false;
  }

  // To-Do Pending to be defined
  interface Token {
  }
}

declare const hapiAuthJwt: {
  plugin: Plugin<void>,
  token: hapiJwt.Token
};

export = hapiAuthJwt;

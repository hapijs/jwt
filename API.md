# Usage

**@hapi/jwt** plugin provides built-in support for JWT authentication for Hapi servers.

## How to register the plugin

```js
// Load modules
const Jwt = require("@hapi/jwt");
const Hapi = require("@hapi/hapi");

const internals = {};

internals.start = async function() {
  const server = Hapi.server({ port: 8000 });
  await server.register(Jwt);
  server.auth.strategy("jwt", "jwt", {
    // provide the shared secret key / json web keyset info
    keys:
      secret |
      {
        uri: jwks.endpoint
      },
    // fields that needs to be verified and respective values
    verify: {
      // audience intended to receive
      aud: "urn:audience:test",
      // issuer of the jwt
      iss: "urn:issuer:test",
      // verify subject of jwt
      sub: false,
      // check expiry - default true
      exp: true,
      // nbf < (nowSec + skewSec)
      nbf: 1556582777,
      // skew secs
      timeSkewSec: 1,
      // max age (secs) of the JWT allowed
      maxAgeSec: 15
    },
    // token validation fn gets executed after token signature verification
    validate: (artifacts, request, h) => {
      return {
        isValid: true,
        credentials: { user: artifacts.decoded.payload.user }
      };
    }
  });

  //set the strategy
  server.auth.default("jwt");
};
```

## Token validation function

You can provide your own custom validation function, that will be invoked after signature verification.The function is invoked by passing the artifacts of the token, request and response toolkit handler. This function should return the Promise that resolves to object having the below properties / you can also throw error. If you throw err, it will invoke the `h.unauthenticated` fn filling the error message (Boom style)

```json
{
  "isValid": true | false,
  "credentials": { obj }, // decoded payload
  // this response will override and be set in response and takeover
  "response": { obj } // any valid object, if any
}
```

## Example (scenario)

```js
async (artifacts, request, h) => {

// successful validation
return {
    isValid : true,
    credentials : {decoded payload},
    response: <any>
};

// failed validation
return {
    isValid : false,
    credentials : null,
    response": <any>
};

// simply throw error
throw new Error('Invalid username or password');

}
```

# Key algorithms supported by @hapi/jwt

- public: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512']
- rsa: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
- hmac: ['HS256', 'HS384', 'HS512']
- none: ['none]

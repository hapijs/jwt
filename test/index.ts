import { Plugin } from '@hapi/hapi';
import * as Lab from '@hapi/lab';

import * as Jwt from '..';

const { expect } = Lab.types;


// Plugin definitions

expect.type<Plugin<void>>(Jwt.plugin);


// Token definitions

const token = Jwt.token.generate(
  {
    aud: 'urn:audience:test',
    iss: 'urn:issuer:test',
    user: 'some_user_name',
    group: 'hapi_community'
  },
  {
    key: 'some_shared_secret',
    algorithm: 'HS512'
  },
  {
    ttlSec: 14400 // 4 hours
  }
);
expect.type<string>(token);

const decodedToken = Jwt.token.decode(token);
expect.type<string>(decodedToken.token);

expect.type<void>(Jwt.token.verify(decodedToken, 'some_shared_secret'));

expect.type<void>(Jwt.token.verifySignature(decodedToken, 'some_shared_secret'));

expect.type<void>(Jwt.token.verifyPayload(decodedToken));

expect.type<void>(Jwt.token.verifyTime(decodedToken));

expect.type<string>(Jwt.token.signature.generate(decodedToken.token, 'HS512', 'some_shared_secret'));

expect.type<boolean>(Jwt.token.signature.verify(decodedToken.raw, 'HS512', 'some_shared_secret'));


// Crypto definitions

expect.type<string>(Jwt.crypto.rsaPublicKeyToPEM('00:aa:18:ab:a4:3b:50:de:ef:38:59:8f:af:87:d2','65537'));


// Utils definitions

expect.type<string>(Jwt.utils.toHex(2020));

expect.type<string>(Jwt.utils.b64stringify({ foo: 'bar'}));

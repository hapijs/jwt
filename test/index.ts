import { Server } from '@hapi/hapi';
import { types } from '@hapi/lab';
import HapiJwt from '..';

async function test() {
  const server = new Server();

  await server.register(HapiJwt);

  server.auth.strategy('my-strategy', 'jwt', {
    keys: '',
    verify: true,
    validate: true,
  });

  types.expect.type<string>(
    HapiJwt.token.generate({}, '', {
      encoding: 'utf-8',
      header: { 'x-custom': 'value' },
      headless: false,
      iat: true,
      now: 123,
      typ: true,
      ttlSec: 456,
    })
  );

  types.expect.type<{ token: string }>(
    HapiJwt.token.decode('', { headless: true })
  );

  types.expect.type<void | never>(
    HapiJwt.token.verify(HapiJwt.token.decode(''), '')
  );
}

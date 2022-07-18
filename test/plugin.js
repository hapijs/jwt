'use strict';

const Code = require('@hapi/code');
const Hapi = require('@hapi/hapi');
const Hoek = require('@hapi/hoek');
const Jwt = require('..');
const Lab = require('@hapi/lab');

const Mock = require('./mock');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Plugin', () => {

    it('authenticates a request (HS256)', async () => {

        const secret = 'some_shared_secret';

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        const token1 = Jwt.token.generate({ user: 'steve', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, secret, { header: { kid: 'some' } });
        const res1 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token1}` } });
        expect(res1.result).to.equal('steve');

        const token2 = Jwt.token.generate({ user: 'steve' }, secret);
        const res2 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token2}` } });
        expect(res2.statusCode).to.equal(401);

        const res3 = await server.inject('/');
        expect(res3.statusCode).to.equal(401);

        const res4 = await server.inject({ url: '/', headers: { authorization: 'Bearer' } });
        expect(res4.statusCode).to.equal(401);

        const res5 = await server.inject({ url: '/', headers: { authorization: 'Bearer ' } });
        expect(res5.statusCode).to.equal(401);

        const res6 = await server.inject({ url: '/', headers: { authorization: 'Bearer a.b' } });
        expect(res6.statusCode).to.equal(401);

        const res7 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token1}x` } });
        expect(res7.statusCode).to.equal(401);
    });

    it('authenticates a request (RSA256 public)', async () => {

        const jwks = await Mock.jwks({ rsa: false, public: true });

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: {
                uri: jwks.endpoint
            },
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        await server.initialize();

        const token = Jwt.token.generate({ user: 'steve', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, jwks.key.private, { header: { kid: jwks.kid } });
        const res = await server.inject({ url: '/', headers: { authorization: `Bearer ${token}` } });
        expect(res.result).to.equal('steve');

        await jwks.server.stop();
    });

    it('authenticates a request (RSA256 rsa)', async () => {

        const jwks = await Mock.jwks({ rsa: true, public: false });

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: {
                uri: jwks.endpoint
            },
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        await server.initialize();

        const token = Jwt.token.generate({ user: 'steve', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, jwks.key.private, { header: { kid: jwks.kid } });
        const res = await server.inject({ url: '/', headers: { authorization: `Bearer ${token}` } });
        expect(res.result).to.equal('steve');

        await jwks.server.stop();
    });

    it('support headless tokens (string)', async () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ user: 'steve', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, secret);

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            headless: token.split('.')[0],
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        const headers = {
            authorization: `Bearer ${token.slice(token.split('.')[0].length + 1)}`
        };

        const res = await server.inject({ url: '/', headers });
        expect(res.result).to.equal('steve');
    });

    it('support headless tokens (object)', async () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ user: 'steve', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, secret, { headless: true });

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            headless: { alg: 'HS256', typ: 'JWT' },
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        const res = await server.inject({ url: '/', headers: { authorization: `Bearer ${token}` } });
        expect(res.result).to.equal('steve');
    });

    it('handles failure when headless is defined and token contains header', async () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ user: 'steve', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, secret);

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            headless: { alg: 'HS256', typ: 'JWT' },
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        const res = await server.inject({ url: '/', headers: { authorization: `Bearer ${token}` } });
        expect(res.statusCode).to.equal(401);
    });

    it('support utf-8 (non latin1 characters)', async () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ user: '史蒂夫', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, secret, { header: { location: '图书馆' } });

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user, location: artifacts.decoded.header.location } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/payload', method: 'GET', handler: (request) => request.auth.credentials.user });
        server.route({ path: '/header', method: 'GET', handler: (request) => request.auth.credentials.location });

        const res1 = await server.inject({ url: '/payload', headers: { authorization: `Bearer ${token}` } });
        expect(res1.result).to.equal('史蒂夫');

        const res2 = await server.inject({ url: '/header', headers: { authorization: `Bearer ${token}` } });
        expect(res2.result).to.equal('图书馆');
    });

    it('authenticates a request (none)', async () => {

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: { algorithms: ['none'] },
            verify: {
                aud: 'urn:audience:test',
                iss: 'urn:issuer:test',
                sub: false
            },
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        const token1 = Jwt.token.generate({ user: 'steve', aud: 'urn:audience:test', iss: 'urn:issuer:test' }, '');
        const res1 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token1}` } });
        expect(res1.result).to.equal('steve');

        const token2 = Jwt.token.generate({ user: 'steve' }, 'some_secret');
        const res2 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token2}` } });
        expect(res2.statusCode).to.equal(401);
    });

    it('supports multiple strategies', async () => {

        const secret = 'some_shared_secret';
        const jwks = await Mock.jwks();

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('secret', 'jwt', {
            keys: secret,
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: false
        });

        server.auth.strategy('rsa', 'jwt', {
            keys: {
                uri: jwks.endpoint
            },
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: false,
            httpAuthScheme: 'Other'
        });

        server.auth.strategy('rsa2', 'jwt', {
            keys: {
                uri: jwks.endpoint
            },
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: false,
            httpAuthScheme: 'Also'
        });

        const handler = (request) => request.auth.credentials.user;
        server.route({ path: '/secret', method: 'GET', options: { auth: 'secret', handler } });
        server.route({ path: '/rsa', method: 'GET', options: { auth: 'rsa', handler } });
        server.route({ path: '/rsa2', method: 'GET', options: { auth: 'rsa2', handler } });
        server.route({ path: '/', method: 'GET', options: { auth: { strategies: ['secret', 'rsa', 'rsa2'] }, handler } });

        await server.initialize();

        const token1 = Jwt.token.generate({ user: 'steve' }, secret);
        const res1 = await server.inject({ url: '/secret', headers: { authorization: `Bearer ${token1}` } });
        expect(res1.result).to.equal('steve');

        const token2 = Jwt.token.generate({ user: 'steve' }, jwks.key.private, { header: { kid: jwks.kid } });
        const res2 = await server.inject({ url: '/rsa', headers: { authorization: `Other ${token2}` } });
        expect(res2.result).to.equal('steve');

        const token3 = Jwt.token.generate({ user: 'steve' }, jwks.key.private, { header: { kid: jwks.kid } });
        const res3 = await server.inject({ url: '/rsa2', headers: { authorization: `Also ${token3}` } });
        expect(res3.result).to.equal('steve');

        const res4 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token1}` } });
        expect(res4.result).to.equal('steve');

        const res5 = await server.inject({ url: '/', headers: { authorization: `Other ${token2}` } });
        expect(res5.result).to.equal('steve');

        const res6 = await server.inject({ url: '/', headers: { authorization: `Also ${token3}` } });
        expect(res6.result).to.equal('steve');
    });

    it('handles failed validate', async () => {

        const secret = 'some_shared_secret';

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: (artifacts, request, h) => {

                if (artifacts.decoded.payload.x === 1) {
                    return { isValid: false };
                }

                if (artifacts.decoded.payload.x === 2) {
                    throw new Error('oops');
                }

                return { response: 'hi!' };
            }
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        const token1 = Jwt.token.generate({ x: 1 }, secret);
        const res1 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token1}` } });
        expect(res1.statusCode).to.equal(401);

        const token2 = Jwt.token.generate({ x: 2 }, secret);
        const res2 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token2}` } });
        expect(res2.statusCode).to.equal(401);

        const token3 = Jwt.token.generate({ x: 3 }, secret);
        const res3 = await server.inject({ url: '/', headers: { authorization: `Bearer ${token3}` } });
        expect(res3.statusCode).to.equal(200);
        expect(res3.result).to.equal('hi!');
    });

    it('skips verify', async () => {

        const secret = 'some_shared_secret';

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            verify: false,
            validate: (artifacts, request, h) => {

                return { isValid: true, credentials: { user: artifacts.decoded.payload.user } };
            }
        });

        server.auth.default('jwt');

        const handler = async (request, h) => {

            await server.auth.verify(request);
            return request.auth.credentials.user;
        };

        server.route({ path: '/', method: 'GET', handler });

        const token = Jwt.token.generate({ user: 'steve' }, 'other_secret');
        const res = await server.inject({ url: '/', headers: { authorization: `Bearer ${token}` } });
        expect(res.result).to.equal('steve');
    });

    it('reverifies token', { timeout: 4000 }, async () => {

        const secret = 'some_shared_secret';

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: secret,
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: false
        });

        server.auth.default('jwt');

        const handler = async (request, h) => {

            await server.auth.verify(request);
            await Hoek.wait(3000);
            try {
                await server.auth.verify(request);
            }
            catch (err) {
                return 'ok';
            }
        };

        server.route({ path: '/', method: 'GET', handler });

        const nowSec = Math.ceil(Date.now() / 1000);
        const token = Jwt.token.generate({ user: 'steve', exp: nowSec + 1 }, secret);
        const res = await server.inject({ url: '/', headers: { authorization: `Bearer ${token}` } });
        expect(res.result).to.equal('ok');
    });

    it('errors on cache warmup error', async () => {

        const jwks = await Mock.jwks({ algorithm: 'RS512' });

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: {
                uri: jwks.endpoint,
                algorithms: ['RS256']       // Does not match - always ignored
            },
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: false
        });

        await expect(server.initialize()).to.reject('JWKS endpoint response contained no valid keys');
        await jwks.server.stop();
    });

    it('errors on uninitialized server', async () => {

        const jwks = await Mock.jwks();

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys: {
                uri: jwks.endpoint
            },
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: false
        });

        server.auth.default('jwt');
        server.route({ path: '/', method: 'GET', handler: (request) => request.auth.credentials.user });

        const token = Jwt.token.generate({ user: 'steve' }, jwks.key.private, { header: { kid: jwks.kid } });
        const res = await server.inject({ url: '/', headers: { authorization: `Bearer ${token}` } });
        expect(res.statusCode).to.equal(500);

        await jwks.server.stop();
    });
});

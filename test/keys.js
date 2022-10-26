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


describe('Keys', () => {

    it('processes key array', async () => {

        const jwks1 = await Mock.jwks({ algorithm: 'RS256', crap: true });
        const jwks2 = await Mock.jwks({ algorithm: 'RS256', kid: jwks1.kid });
        const jwks3 = await Mock.jwks({ algorithm: 'RS256' });

        const keys = [
            'some_shared_secret',
            Buffer.from('another_shared_secret'),
            {
                key: 'wrapped_secret_without_algorithms',
                kid: 'explicit'
            },
            {
                key: Buffer.from('wrapped_buffer_without_algorithms'),
                kid: 'some'
            },
            {
                key: 'wrapped_secret_with_algorithms',
                algorithms: ['HS256', 'HS384']
            },
            {
                key: Buffer.from('wrapped_buffer_with_algorithms'),
                algorithms: ['HS384']
            },
            (artifacts, request) => {

                return [
                    { key: 'dynamic_secret', algorithms: ['HS256'] },
                    '',
                    Buffer.from('some_other_secret')
                ];
            },
            (artifacts, request) => {

                return {
                    key: 'dynamic_secret',
                    algorithms: ['HS384']
                };
            },
            {
                uri: jwks1.endpoint
            },
            {
                uri: jwks2.endpoint,
                algorithms: ['RS256', 'RS512']
            },
            {
                uri: jwks3.endpoint
            },
            {
                key: '',
                algorithms: ['none']
            }
        ];

        const server = Hapi.server();
        await server.register(Jwt);

        server.auth.strategy('jwt', 'jwt', {
            keys,
            verify: {
                aud: false,
                iss: false,
                sub: false
            },
            validate: false
        });

        server.auth.default('jwt');

        await server.initialize();

        const provider = server.plugins.jwt._providers[0];

        const tests = [
            [{ decoded: { header: { alg: 'HS256' } } }, 7],
            [{ decoded: { header: { alg: 'HS256', kid: 'some' } } }, 6],
            [{ decoded: { header: { alg: 'HS384' } } }, 8],
            [{ decoded: { header: { alg: 'RS256', kid: jwks1.kid } } }, 2],
            [{ decoded: { header: { alg: 'RS256', kid: 'other' } } }, 0],
            [{ decoded: { header: { alg: 'RS256' } } }, 0]
        ];

        for (const [artifacts, count] of tests) {
            await provider.assign(artifacts, {});
            if (count) {
                expect(artifacts.keys).to.have.length(count);
            }
            else {
                expect(artifacts.keys).to.not.exist();
            }
        }

        await jwks1.server.stop();
        await jwks2.server.stop();
        await jwks3.server.stop();
    });

    describe('assign()', () => {

        it('reports remote source error', async () => {

            const jwks = await Mock.jwks();

            const server = Hapi.server();
            await server.register(Jwt);

            server.auth.strategy('jwt', 'jwt', {
                keys: [
                    {
                        uri: jwks.endpoint
                    },
                    jwks.key.public
                ],
                verify: {
                    aud: false,
                    iss: false,
                    sub: false
                },
                validate: false,
                cache: {
                    expiresIn: 10,
                    staleIn: 5,
                    staleTimeout: 1,
                    generateTimeout: 10000          // Extra large for Windows to avoid catbox cache timeout waiting for disconnected error
                }
            });

            await server.initialize();

            await jwks.server.stop();
            await Hoek.wait(10);

            const provider = server.plugins.jwt._providers[0];
            const artifacts = { decoded: { header: { alg: 'RS256', kid: jwks.kid } } };
            await provider.assign(artifacts, {});

            expect(artifacts.errors).to.have.length(1);
            expect(artifacts.errors[0]).to.be.an.error('JWKS endpoint error');
        });

        it('skips failing remote source', async () => {

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
                validate: false,
                cache: {
                    expiresIn: 10,
                    staleIn: 5,
                    staleTimeout: 1,
                    generateTimeout: 100
                }
            });

            await server.initialize();

            await jwks.server.stop();
            await Hoek.wait(10);

            const provider = server.plugins.jwt._providers[0];
            const artifacts = { decoded: { header: { alg: 'RS256', kid: jwks.kid } } };

            await expect(provider.assign(artifacts, {})).to.reject('Failed to obtain keys');
        });

        it('skips failing dynamic source', async () => {

            const server = Hapi.server();
            await server.register(Jwt);

            server.auth.strategy('jwt', 'jwt', {
                keys: () => {

                    throw new Error('sorry');
                },
                verify: {
                    aud: false,
                    iss: false,
                    sub: false
                },
                validate: false,
                cache: {
                    expiresIn: 10,
                    staleIn: 5,
                    staleTimeout: 1,
                    generateTimeout: 100
                }
            });

            await server.initialize();

            const provider = server.plugins.jwt._providers[0];
            const artifacts = { decoded: { header: { alg: 'HS256' } } };

            await expect(provider.assign(artifacts, {})).to.reject('Failed to obtain keys');
        });
    });

    describe('jwks()', () => {

        it('reports remote source missing payload error', async () => {

            const jwks = Hapi.server();
            const path = '/.well-known/jwks.json';
            jwks.route({ method: 'GET', path, handler: () => '' });
            await jwks.start();

            const server = Hapi.server();
            await server.register(Jwt);

            server.auth.strategy('jwt', 'jwt', {
                keys: {
                    uri: `http://0.0.0.0:${jwks.info.port}${path}`
                },
                verify: {
                    aud: false,
                    iss: false,
                    sub: false
                },
                validate: false
            });

            await expect(server.initialize()).to.reject('JWKS endpoint returned empty payload');
            await jwks.stop();
        });

        it('reports remote source invalid payload error', async () => {

            for (const payload of [{}, { keys: 123 }, { keys: [] }]) {
                const jwks = Hapi.server();
                const path = '/.well-known/jwks.json';
                jwks.route({ method: 'GET', path, handler: () => payload });
                await jwks.start();

                const server = Hapi.server();
                await server.register(Jwt);

                server.auth.strategy('jwt', 'jwt', {
                    keys: {
                        uri: `http://0.0.0.0:${jwks.info.port}${path}`
                    },
                    verify: {
                        aud: false,
                        iss: false,
                        sub: false
                    },
                    validate: false
                });

                await expect(server.initialize()).to.reject('JWKS endpoint returned invalid payload');
                await jwks.stop();
            }
        });

        it('errors on no valid rsa keys', async () => {

            const jwks = await Mock.jwks({ algorithm: 'RS512', public: false });

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
    });

    describe('algorithms()', () => {

        it('sets default algorithms for rsa', async () => {

            const jwks = await Mock.jwks({ public: false, algorithm: false });

            const server = Hapi.server();
            await server.register(Jwt);

            server.auth.strategy('jwt', 'jwt', {
                keys: [
                    {
                        uri: jwks.endpoint
                    }
                ],
                verify: {
                    aud: false,
                    iss: false,
                    sub: false
                },
                validate: false
            });

            await server.initialize();

            const provider = server.plugins.jwt._providers[0];
            expect((await provider._cache.get(jwks.endpoint)).get(jwks.kid).algorithms).to.equal(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

            await jwks.server.stop();
        });

        it('sets default algorithms for public', async () => {

            const jwks = await Mock.jwks({ rsa: false, algorithm: false });

            const server = Hapi.server();
            await server.register(Jwt);

            server.auth.strategy('jwt', 'jwt', {
                keys: [
                    {
                        uri: jwks.endpoint
                    }
                ],
                verify: {
                    aud: false,
                    iss: false,
                    sub: false
                },
                validate: false
            });

            await server.initialize();

            const provider = server.plugins.jwt._providers[0];
            expect((await provider._cache.get(jwks.endpoint)).get(jwks.kid).algorithms).to.equal(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);

            await jwks.server.stop();
        });

        it('use specified algorithms for rsa', async () => {

            const jwks = await Mock.jwks({ public: false, algorithm: false });

            const server = Hapi.server();
            await server.register(Jwt);

            server.auth.strategy('jwt', 'jwt', {
                keys: [
                    {
                        uri: jwks.endpoint,
                        algorithms: ['RS512', 'PS512']
                    }
                ],
                verify: {
                    aud: false,
                    iss: false,
                    sub: false
                },
                validate: false
            });

            await server.initialize();

            const provider = server.plugins.jwt._providers[0];
            expect((await provider._cache.get(jwks.endpoint)).get(jwks.kid).algorithms).to.equal(['RS512', 'PS512']);

            await jwks.server.stop();
        });
    });
});

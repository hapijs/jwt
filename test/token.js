'use strict';

const Code = require('@hapi/code');
const Hoek = require('@hapi/hoek');
const Jwt = require('..');
const Lab = require('@hapi/lab');

const Mock = require('./mock');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Token', () => {

    it('creates and verifies a token', () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ test: 'ok' }, secret);
        const artifacts = Jwt.token.decode(token);
        Jwt.token.verify(artifacts, secret);

        expect(artifacts.decoded).to.equal({
            header: { alg: 'HS256', typ: 'JWT' },
            payload: { test: 'ok', iat: artifacts.decoded.payload.iat },
            signature: artifacts.decoded.signature
        });
    });

    it('creates and verifies a token (HS512)', () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ test: 'ok' }, { key: secret, algorithm: 'HS512' });
        const artifacts = Jwt.token.decode(token);
        Jwt.token.verify(artifacts, secret);

        expect(artifacts.decoded).to.equal({
            header: { alg: 'HS512', typ: 'JWT' },
            payload: { test: 'ok', iat: artifacts.decoded.payload.iat },
            signature: artifacts.decoded.signature
        });
    });

    it('creates and verifies a token (none)', () => {

        const token = Jwt.token.generate({ test: 'ok' }, '');
        const artifacts = Jwt.token.decode(token);
        Jwt.token.verify(artifacts, '');

        expect(artifacts.decoded).to.equal({
            header: { alg: 'none', typ: 'JWT' },
            payload: { test: 'ok', iat: artifacts.decoded.payload.iat },
            signature: ''
        });
    });

    it('creates and verifies a token (no typ)', () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ test: 'ok' }, secret, { typ: false });
        const artifacts = Jwt.token.decode(token);
        Jwt.token.verify(artifacts, secret);

        expect(artifacts.decoded).to.equal({
            header: { alg: 'HS256' },
            payload: { test: 'ok', iat: artifacts.decoded.payload.iat },
            signature: artifacts.decoded.signature
        });
    });

    it('creates and verifies a headless token', () => {

        const secret = 'some_shared_secret';
        const token = Jwt.token.generate({ test: 'ok' }, secret, { headless: true });
        const artifacts = Jwt.token.decode(token, { headless: { alg: 'HS256', typ: 'JWT' } });

        expect(artifacts.decoded).to.equal({
            header: { alg: 'HS256', typ: 'JWT' },
            payload: { test: 'ok', iat: artifacts.decoded.payload.iat },
            signature: artifacts.decoded.signature
        });
    });

    describe('generate()', () => {

        it('creates and verifies a token (custom now)', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, { key: secret }, { now: 1556520613637 });
            const artifacts = Jwt.token.decode(token);
            Jwt.token.verify(artifacts, secret);

            expect(artifacts.decoded).to.equal({
                header: { alg: 'HS256', typ: 'JWT' },
                payload: { test: 'ok', iat: 1556520613 },
                signature: 'YjUQB7jHyZyarkUZe0Lx4vngqZaIQTZU24k71jJVHBo'
            });
        });

        it('creates and verifies a token (custom iat)', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok', iat: 1556520613 }, { key: secret }, { encoding: 'utf8' });
            const artifacts = Jwt.token.decode(token);
            Jwt.token.verify(artifacts, secret);

            expect(artifacts.decoded).to.equal({
                header: { alg: 'HS256', typ: 'JWT' },
                payload: { test: 'ok', iat: 1556520613 },
                signature: 'YjUQB7jHyZyarkUZe0Lx4vngqZaIQTZU24k71jJVHBo'
            });
        });

        it('creates and verifies a token (custom header fields)', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, { key: secret }, { now: 1556520613637, header: { extra: 'value' } });
            const artifacts = Jwt.token.decode(token);
            Jwt.token.verify(artifacts, secret);

            expect(artifacts.decoded).to.equal({
                header: { alg: 'HS256', typ: 'JWT', extra: 'value' },
                payload: { test: 'ok', iat: 1556520613 },
                signature: 'm1cWB5oNHM_ygxoN6eVlZPBKq5ysyJ9vR8e7ikM0gBU'
            });
        });

        it('creates token with ttl', async () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, { key: secret }, { ttlSec: 1 });
            const artifacts = Jwt.token.decode(token);
            Jwt.token.verify(artifacts, secret);

            await Hoek.wait(1000);

            expect(() => Jwt.token.verify(artifacts, secret)).to.throw('Token expired');
        });

        it('ignores ttl when exp present', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok', exp: 123 }, { key: secret }, { ttlSec: 1 });
            const artifacts = Jwt.token.decode(token);
            expect(artifacts.decoded.payload.exp).to.equal(123);
        });
    });

    describe('decode()', () => {

        it('decodes a headless token (encoded)', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, secret);
            const head = token.split('.', 1)[0];
            const tail = token.substring(head.length + 1);
            const artifacts = Jwt.token.decode(tail, { headless: head });
            Jwt.token.verify(artifacts, secret);

            expect(artifacts.decoded).to.equal({
                header: { alg: 'HS256', typ: 'JWT' },
                payload: { test: 'ok', iat: artifacts.decoded.payload.iat },
                signature: artifacts.decoded.signature
            });
        });

        it('decodes a headless token (object)', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, secret);
            const orig = Jwt.token.decode(token);

            const artifacts = Jwt.token.decode(orig.raw.payload + '.' + orig.raw.signature, { headless: orig.decoded.header });
            Jwt.token.verify(artifacts, secret);

            expect(artifacts.decoded).to.equal({
                header: { alg: 'HS256', typ: 'JWT' },
                payload: { test: 'ok', iat: artifacts.decoded.payload.iat },
                signature: artifacts.decoded.signature
            });
        });

        it('errors on incorrect number of parts', () => {

            expect(() => Jwt.token.decode('a')).to.throw('Invalid token structure');
            expect(() => Jwt.token.decode('a.b')).to.throw('Invalid token structure');
        });

        it('errors on invalid parts', () => {

            expect(() => Jwt.token.decode('@.abc.def')).to.throw('Invalid token header part');
            expect(() => Jwt.token.decode('abc.@.def')).to.throw('Invalid token payload part');
            expect(() => Jwt.token.decode('abc.def.@')).to.throw('Invalid token signature part');
        });

        it('errors on missing header', () => {

            expect(() => Jwt.token.decode('.a.b')).to.throw('Invalid token missing header');
        });

        it('errors on non JWT token', () => {

            const token = `${Jwt.utils.b64stringify({ alg: 'none', typ: 'Not JWT' })}.${Jwt.utils.b64stringify({}, 'utf8')}.`;
            expect(() => Jwt.token.decode(token)).to.throw('Token is not a JWT');
        });

        it('errors on invalid payload', () => {

            expect(() => Jwt.token.decode(`${Jwt.utils.b64stringify({ typ: 'JWT', alg: 'none' })}.xxx.`)).to.throw('Invalid token payload');
            expect(() => Jwt.token.decode(`${Jwt.utils.b64stringify({ typ: 'JWT', alg: 'none' })}.${Jwt.utils.b64stringify(123)}.`)).to.throw('Invalid token payload');
            expect(() => Jwt.token.decode(`${Jwt.utils.b64stringify({ typ: 'JWT', alg: 'none' })}.${Jwt.utils.b64stringify([])}.`)).to.throw('Invalid token payload');
        });

        it('errors on missing algorithm', () => {

            const token = `${Jwt.utils.b64stringify({ typ: 'JWT' })}.${Jwt.utils.b64stringify({}, 'utf8')}.`;
            expect(() => Jwt.token.decode(token)).to.throw('Token header missing alg attribute');
        });

        it('errors on header present in token and headless provided', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, secret);
            expect(() => Jwt.token.decode(token, { headless: { alg: 'HS256', typ: 'JWT' } })).to.throw('Token contains header');
        });
    });

    describe('verifySignature()', () => {

        it('validates signature', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, secret);
            const artifacts = Jwt.token.decode(token);

            Jwt.token.verifySignature(artifacts, { key: secret, algorithm: 'HS256' });
            Jwt.token.verifySignature(artifacts, { key: secret, algorithms: ['HS256', 'HS512'] });
        });

        it('invalidates signature', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, secret);
            const artifacts = Jwt.token.decode(token);

            Jwt.token.verify(artifacts, secret);

            expect(() => Jwt.token.verify(artifacts, 'wrong_secret')).to.throw('Invalid token signature');
        });
    });

    describe('verifyPayload()', () => {

        it('validates claims', () => {

            const payload = {
                iss: 'urn:example',
                sub: 'urn:subject',
                jti: 'abc',
                nonce: 'xyz'
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '')).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { iss: payload.iss })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { iss: [payload.iss] })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { sub: payload.sub })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { jti: payload.jti })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { nonce: payload.nonce })).to.not.throw();

            expect(() => Jwt.token.verify(artifacts, '', { iss: 'wrong' })).to.throw('Token payload iss value not allowed');
            expect(() => Jwt.token.verify(artifacts, '', { iss: ['wrong'] })).to.throw('Token payload iss value not allowed');
            expect(() => Jwt.token.verify(artifacts, '', { sub: 'wrong' })).to.throw('Token payload sub value not allowed');
            expect(() => Jwt.token.verify(artifacts, '', { jti: 'wrong' })).to.throw('Token payload jti value not allowed');
            expect(() => Jwt.token.verify(artifacts, '', { nonce: 'wrong' })).to.throw('Token payload nonce value not allowed');
        });

        it('validates missing claims', () => {

            const token = Jwt.token.generate({}, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '')).to.not.throw();

            expect(() => Jwt.token.verify(artifacts, '', { iss: 'a' })).to.throw('Token missing payload iss value');
            expect(() => Jwt.token.verify(artifacts, '', { sub: 'a' })).to.throw('Token missing payload sub value');
            expect(() => Jwt.token.verify(artifacts, '', { jti: 'a' })).to.throw('Token missing payload jti value');
            expect(() => Jwt.token.verify(artifacts, '', { nonce: 'a' })).to.throw('Token missing payload nonce value');
        });

        it('validates audience', () => {

            const payload = {
                aud: 'a1'
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '')).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: 'a1' })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: ['a1'] })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: ['a1', 'b1'] })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: /a1/ })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: [/a1/] })).to.not.throw();

            expect(() => Jwt.token.verify(artifacts, '', { aud: 'wrong' })).to.throw('Token audience is not allowed');
            expect(() => Jwt.token.verify(artifacts, '', { aud: ['wrong'] })).to.throw('Token audience is not allowed');
            expect(() => Jwt.token.verify(artifacts, '', { aud: /wrong/ })).to.throw('Token audience is not allowed');
        });

        it('validates audiences', () => {

            const payload = {
                aud: ['a1', 'b1']
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '')).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: 'a1' })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: ['a1'] })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { aud: 'b1' })).to.not.throw();

            expect(() => Jwt.token.verify(artifacts, '', { aud: 'wrong' })).to.throw('Token audience is not allowed');
            expect(() => Jwt.token.verify(artifacts, '', { aud: ['wrong'] })).to.throw('Token audience is not allowed');
        });

        it('errors on missing audience', () => {

            const token = Jwt.token.generate({}, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '', { aud: ['wrong'] })).to.throw('Token missing payload aud value');
        });

        it('validates expiration', () => {

            const now = 1556582767980;

            const payload = {
                exp: 1556582770
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '', { exp: false })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { now })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { now: now + 10000, timeSkewSec: 15 })).to.not.throw();

            expect(() => Jwt.token.verify(artifacts, '')).to.throw('Token expired');
            expect(() => Jwt.token.verify(artifacts, '', { now: now + 10000 })).to.throw('Token expired');
            expect(() => Jwt.token.verify(artifacts, '', { now: now + 10000, timeSkewSec: 1 })).to.throw('Token expired');
        });

        it('errors on invalid expiration', () => {

            const payload = {
                exp: '123'
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '')).to.throw('Invalid payload exp value');
        });

        it('validates max age', () => {

            const now = 1556582767980;

            const payload = {
                iat: 1556582767
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '', { iat: false })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { now })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { now: now + 10000, maxAgeSec: 10 })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { now: now + 10000, timeSkewSec: 15, maxAgeSec: 5 })).to.not.throw();

            expect(() => Jwt.token.verify(artifacts, '', { now: now + 10000, maxAgeSec: 5 })).to.throw('Token maximum age exceeded');
            expect(() => Jwt.token.verify(artifacts, '', { now: now + 10000, maxAgeSec: 5, timeSkewSec: 1 })).to.throw('Token maximum age exceeded');
        });

        it('errors on invalid iat', () => {

            const token = Jwt.token.generate({ iat: '123' }, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '', { maxAgeSec: 1000 })).to.throw('Missing or invalid payload iat value');
        });

        it('errors on null iat', () => {

            const token = Jwt.token.generate({ iat: null }, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '', { maxAgeSec: 1000 })).to.throw('Missing or invalid payload iat value');
        });

        it('errors on missing iat', () => {

            const token = Jwt.token.generate({}, '', { iat: false });
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '', { maxAgeSec: 1000 })).to.throw('Missing or invalid payload iat value');
        });

        it('validates not before', () => {

            const now = 1556582767980;

            const payload = {
                nbf: 1556582777
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '')).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { now, nbf: false })).to.not.throw();
            expect(() => Jwt.token.verify(artifacts, '', { now, timeSkewSec: 15 })).to.not.throw();

            expect(() => Jwt.token.verify(artifacts, '', { now })).to.throw('Token not yet active');
            expect(() => Jwt.token.verify(artifacts, '', { now, timeSkewSec: 1 })).to.throw('Token not yet active');
        });

        it('errors on invalid nbf', () => {

            const token = Jwt.token.generate({ nbf: '123' }, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verify(artifacts, '')).to.throw('Invalid payload nbf value');
        });
    });

    describe('verifyTime()', () => {

        it('validates expiration', () => {

            const now = 1556582767980;

            const payload = {
                exp: 1556582770
            };

            const token = Jwt.token.generate(payload, '');
            const artifacts = Jwt.token.decode(token);

            expect(() => Jwt.token.verifyTime(artifacts, { exp: false })).to.not.throw();
            expect(() => Jwt.token.verifyTime(artifacts, { now })).to.not.throw();
            expect(() => Jwt.token.verifyTime(artifacts, { now: now + 10000, timeSkewSec: 15 })).to.not.throw();

            expect(() => Jwt.token.verifyTime(artifacts)).to.throw('Token expired');
            expect(() => Jwt.token.verifyTime(artifacts, { now: now + 10000 })).to.throw('Token expired');
            expect(() => Jwt.token.verifyTime(artifacts, { now: now + 10000, timeSkewSec: 1 })).to.throw('Token expired');
        });
    });

    describe('key()', () => {

        it('errors on incompatible key', () => {

            const secret = 'some_shared_secret';
            const token = Jwt.token.generate({ test: 'ok' }, secret);
            const artifacts = Jwt.token.decode(token);
            expect(() => Jwt.token.verify(artifacts, Mock.pair().public)).to.throw('Unsupported algorithm');
        });
    });
});

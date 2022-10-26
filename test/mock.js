'use strict';

const Crypto = require('crypto');
const Cryptiles = require('@hapi/cryptiles');
const Forge = require('node-forge');
const Hapi = require('@hapi/hapi');
const Jwt = require('..');
const Rsa = require('node-rsa');


const internals = {};


exports.jwks = async function (options = {}) {

    const server = Hapi.server();
    const path = '/.well-known/jwks.json';
    server.route({ method: 'GET', path, handler: () => server.app.jwks });
    await server.start();

    const key = {
        kid: options.kid || Cryptiles.randomString(24),
        kty: 'RSA',
        use: 'sig'
    };

    if (options.algorithm !== false) {
        key.alg = options.algorithm || 'RS256';
    }

    server.app.jwks = { keys: [key] };

    const pair = exports.pair();

    if (options.public !== false) {
        const now = new Date();
        const cert = Forge.pki.createCertificate();
        cert.publicKey = Forge.pki.publicKeyFromPem(pair.public);
        cert.serialNumber = parseInt(Cryptiles.randomDigits(15)).toString(16);
        cert.validity.notBefore = now;
        cert.validity.notAfter = now;
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        cert.setSubject([{ name: 'commonName', value: 'http://example.com' }]);
        cert.sign(Forge.pki.privateKeyFromPem(pair.private));
        const certDer = Forge.util.encode64(Forge.asn1.toDer(Forge.pki.certificateToAsn1(cert)).getBytes());
        key.x5c = [certDer];
        key.x5t = key.kid;
    }

    if (options.rsa !== false) {
        const rsa = new Rsa();
        rsa.importKey(pair.private);
        const { n, e } = rsa.exportKey('components');
        key.e = Buffer.isBuffer(e) ? e.toString('base64') : Buffer.from(Jwt.utils.toHex(e), 'hex').toString('base64');
        key.n = n.toString('base64');
    }

    if (options.crap) {
        server.app.jwks.keys.push({ use: 'mock' });
        server.app.jwks.keys.push({ use: 'sig', kty: 'OTHER' });
        server.app.jwks.keys.push({ use: 'sig', kty: 'RSA' });
        server.app.jwks.keys.push({ use: 'sig', kty: 'RSA', kid: 'test', x5c: [] });
        server.app.jwks.keys.push({ use: 'sig', kty: 'RSA', kid: 'test', n: 'b64' });
    }

    return {
        server,
        // This is the host specifically for node v18 w/ hapi v20, re: default host and ipv6 support. See also hapijs/hapi#4357.
        endpoint: `http://0.0.0.0:${server.info.port}${path}`,
        kid: key.kid,
        key: pair
    };
};


exports.pair = function (type = 'rsa', bits = 2048) {

    // RSA

    if (type === 'rsa') {
        const pair = Forge.pki.rsa.generateKeyPair(bits);
        const keys = {
            private: Forge.pki.privateKeyToPem(pair.privateKey),
            public: Forge.pki.publicKeyToPem(pair.publicKey)
        };

        return keys;
    }

    // EdDSA - ed25519
    // EdDSA - ed448

    if (type === 'EdDSA') {
        const crv = bits;

        const { privateKey, publicKey } = Crypto.generateKeyPairSync(crv);
        const keys = {
            private: privateKey,
            public: publicKey
        };

        return keys;
    }

    // EC

    return internals.cert[type][bits];
};


internals.cert = {
    ec: {
        256: {},
        384: {},
        512: {}
    }
};


// openssl ecparam -name prime256v1 -genkey

internals.cert.ec['256'].private = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILQzd1wrxa3MtO46qgOwK2xyVbXUn3J/Bz1E51sAZfCsoAoGCCqGSM49
AwEHoUQDQgAEMPMwBlhlHhfWY9S8g35VIbiyq121JGeYEctjKnAuMqOsT05xLsWR
xP87kTuGZned4BPFbYnUHIXlDCKidFWQeg==
-----END EC PRIVATE KEY-----`;


// openssl ec -in private.pem -pubout

internals.cert.ec['256'].public = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMPMwBlhlHhfWY9S8g35VIbiyq121
JGeYEctjKnAuMqOsT05xLsWRxP87kTuGZned4BPFbYnUHIXlDCKidFWQeg==
-----END PUBLIC KEY-----`;


// openssl ecparam -name secp384r1 -genkey

internals.cert.ec['384'].private = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAhNOjAJzy3C9Q5nMzULpoTi+Dq7DAckG01kv4+KOz8EU1uJUuwKaE2
g04RIhELbzOgBwYFK4EEACKhZANiAATBgd1i3IoRpHQKQh4nQBlZahhicDp0Z3rv
8isjvXzanp/qi6+jy+cqozNgTYW6EPb0iXFjr7tK3sDWqLzn+XSV4ExfLZnI77EF
Xp4efGx39zTeet5g2d+FiPhS7eDGoMg=
-----END EC PRIVATE KEY-----`;


// openssl ec -in private.pem -pubout

internals.cert.ec['384'].public = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEwYHdYtyKEaR0CkIeJ0AZWWoYYnA6dGd6
7/IrI7182p6f6ouvo8vnKqMzYE2FuhD29IlxY6+7St7A1qi85/l0leBMXy2ZyO+x
BV6eHnxsd/c03nreYNnfhYj4Uu3gxqDI
-----END PUBLIC KEY-----`;


// openssl ecparam -name secp521r1 -genkey

internals.cert.ec['512'].private = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAPcFy9KaAf2xDTLrmMq/3xEw6MOgUBgrjdehScfbDcoeypJNFuGBt
XXFw0oTkm7zXHmtOU1jOVSKAiNm2lBL+jk2gBwYFK4EEACOhgYkDgYYABAF+MMlz
GpiYmAij2dDzeBJAbj2Bdip+uUjekEA4clOtSDQz6F+Nxqfj2fZUk1x/Kd+C5dZ5
iE+uX7FqYDxyra1f3QB1KpicJ/q1bhiDn9nuBDyEglSlDYbYC59hYdarMZcW6DvA
Nc6GnwTIxJr/O0X7geS7YOVtSsyYcNnwxumnKkT4Aw==
-----END EC PRIVATE KEY-----`;


// openssl ec -in private.pem -pubout

internals.cert.ec['512'].public = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBfjDJcxqYmJgIo9nQ83gSQG49gXYq
frlI3pBAOHJTrUg0M+hfjcan49n2VJNcfynfguXWeYhPrl+xamA8cq2tX90AdSqY
nCf6tW4Yg5/Z7gQ8hIJUpQ2G2AufYWHWqzGXFug7wDXOhp8EyMSa/ztF+4Hku2Dl
bUrMmHDZ8MbppypE+AM=
-----END PUBLIC KEY-----`;

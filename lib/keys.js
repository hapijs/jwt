'use strict';

const Boom = require('@hapi/boom');
const Wreck = require('@hapi/wreck');

const Crypto = require('./crypto');


const internals = {
    keyAlgo: {
        none: ['none'],
        public: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'],
        rsa: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
        hmac: ['HS256', 'HS384', 'HS512']
    },
    certRx: {
        public: /^[\s\-]*BEGIN (?:CERTIFICATE)|(?:PUBLIC KEY)/,
        rsa: /^[\s\-]*BEGIN RSA (?:PRIVATE)|(?:PUBLIC)/
    }
};


internals.supportedAlgorithms = internals.keyAlgo.public.concat(internals.keyAlgo.hmac);


module.exports = internals.Provider = class {

    constructor(server, options) {

        this._server = server;
        this._settings = options;
        this._cache = null;

        // Split sources

        this._statics = [];
        this._dynamics = [];
        this._remotes = new Map();

        for (const key of options.keys) {
            if (Buffer.isBuffer(key) ||
                typeof key === 'string') {

                this._statics.push({ key, algorithms: internals.Provider.keyAlgorithms(key) });
            }
            else if (typeof key === 'function') {
                this._dynamics.push(key);
            }
            else if (key.key !== undefined) {
                this._statics.push({ key: key.key, algorithms: key.algorithms || internals.Provider.keyAlgorithms(key.key), kid: key.kid });
            }
            else {
                this._remotes.set(key.uri, { algorithms: key.algorithms, wreck: { json: 'force', headers: key.headers, rejectUnauthorized: key.rejectUnauthorized } });
            }
        }

        // Register provider

        this.hasJwks = !!this._remotes.size;
        this._server.plugins.jwt._providers.push(this);
    }

    initialize(segment) {

        if (!this.hasJwks) {
            return;
        }

        const cache = Object.assign({}, this._settings.cache);
        cache.segment = segment;
        cache.cache = this._server.plugins.jwt._cacheName;
        cache.generateFunc = internals.jwks(this);
        this._cache = this._server.cache(cache);

        // Warmup cache

        const pending = [];
        for (const uri of this._remotes.keys()) {
            pending.push(this._cache.get(uri));
        }

        return Promise.all(pending);
    }

    async assign(artifacts, request) {

        const errors = [];
        const keys = [];

        // Add static keys

        internals.append(keys, this._statics, artifacts.decoded.header);

        // Add matching remote keys

        const kid = artifacts.decoded.header.kid;
        if (kid &&
            this._remotes.size) {

            if (!this._cache) {
                throw Boom.internal('Server is not initialized');
            }

            for (const uri of this._remotes.keys()) {
                try {
                    const map = await this._cache.get(uri);
                    internals.append(keys, map.get(kid), artifacts.decoded.header);
                }
                catch (err) {
                    errors.push(err);
                }
            }
        }

        // Generate dynamic keys

        for (const method of this._dynamics) {
            try {
                internals.append(keys, await method(artifacts, request), artifacts.decoded.header);
            }
            catch (err) {
                errors.push(err);
            }
        }

        if (!keys.length) {
            if (errors.length) {
                throw Boom.internal('Failed to obtain keys', errors);
            }

            return;
        }

        if (errors.length) {
            artifacts.errors = errors;
        }

        artifacts.keys = keys;
    }

    static get supportedAlgorithms() {

        return internals.supportedAlgorithms;
    }

    static keyAlgorithms(key) {

        if (!key) {
            return internals.keyAlgo.none;
        }

        const keyString = key.toString();

        if (internals.certRx.public.test(keyString)) {
            return internals.keyAlgo.public;
        }

        if (internals.certRx.rsa.test(keyString)) {
            return internals.keyAlgo.rsa;
        }

        return internals.keyAlgo.hmac;
    }
};


internals.append = function (to, from, { alg, kid }) {

    if (!from) {
        return;
    }

    const values = Array.isArray(from) ? from : [from];
    for (const value of values) {
        const key = internals.normalize(value);
        if (key.algorithms.includes(alg) &&
            (!kid || !key.kid || kid === key.kid)) {

            to.push({ key: key.key, algorithm: alg, kid: key.kid });
        }
    }
};


internals.normalize = function (key) {

    if (typeof key === 'string' ||
        Buffer.isBuffer(key)) {

        return { key, algorithms: internals.Provider.keyAlgorithms(key) };
    }

    return key;
};


internals.jwks = function (provider) {

    return async function (uri) {

        const remote = provider._remotes.get(uri);

        try {
            var { payload } = await Wreck.get(uri, remote.wreck);
        }
        catch (err) {
            throw Boom.internal('JWKS endpoint error', err);
        }

        if (!payload) {
            throw Boom.internal('JWKS endpoint returned empty payload', { uri });
        }

        const source = payload.keys;
        if (!source ||
            !Array.isArray(source) ||
            !source.length) {

            throw Boom.internal('JWKS endpoint returned invalid payload', { uri, payload });
        }

        const keys = new Map();
        for (const key of source) {
            if (key.use !== 'sig' ||
                key.kty !== 'RSA' ||
                !key.kid) {

                continue;
            }

            if (key.x5c &&
                key.x5c.length) {

                const algorithms = internals.algorithms(key, remote, 'public');
                if (algorithms) {
                    keys.set(key.kid, { key: Crypto.certToPEM(key.x5c[0]), algorithms });
                }
            }
            else if (key.n &&
                key.e) {

                const algorithms = internals.algorithms(key, remote, 'rsa');
                if (algorithms) {
                    keys.set(key.kid, { key: Crypto.rsaPublicKeyToPEM(key.n, key.e), algorithms });
                }
            }
        }

        if (!keys.size) {
            throw Boom.internal('JWKS endpoint response contained no valid keys', { uri, payload });
        }

        return keys;
    };
};


internals.algorithms = function (key, remote, type) {

    if (key.alg) {
        if (!remote.algorithms ||
            remote.algorithms.includes(key.alg)) {

            return [key.alg];
        }

        return null;
    }

    if (remote.algorithms) {
        return remote.algorithms;
    }

    return internals.keyAlgo[type];
};

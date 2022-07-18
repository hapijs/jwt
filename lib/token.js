'use strict';

const Bourne = require('@hapi/bourne');

const Crypto = require('./crypto');
const Keys = require('./keys');
const Utils = require('./utils');


const internals = {
    partRx: /^[\w\-]*$/,
    parts: ['header', 'payload', 'signature'],
    headless: Symbol('headless')
};


exports.generate = function (payload, secret, options = {}) {

    const { key, algorithms } = internals.secret(secret);
    let content = payload;
    const baseHeader = { alg: algorithms[0] };

    const clone = () => {

        if (content === payload) {
            content = Object.assign({}, content);       // Shallow cloned
        }
    };

    if (content.iat === undefined &&
        options.iat !== false) {

        clone();
        content.iat = internals.tsSecs(options.now);
    }

    if (content.exp === undefined &&
        options.ttlSec) {

        clone();
        content.exp = options.ttlSec + internals.tsSecs(options.now);
    }

    if (options.typ !== false) {
        baseHeader.typ = 'JWT';
    }

    const header = Object.assign(baseHeader, options.header);
    const value = `${Utils.b64stringify(header)}.${Utils.b64stringify(content)}`;
    const signature = Crypto.generate(value, header.alg, key);

    if (options.headless === true) {
        const parts = value.split('.');
        return `${parts[1]}.${signature}`;
    }

    return `${value}.${signature}`;
};


exports.decode = function (token, options = {}) {

    const artifacts = {
        token,
        decoded: {},
        raw: {}
    };

    const parts = token.split('.');

    if (parts.length === 3) {
        if (options.headless) {
            throw internals.error('Token contains header', artifacts);
        }

        artifacts.raw = { header: parts[0], payload: parts[1], signature: parts[2] };
        artifacts.decoded.header = internals.b64parse(artifacts.raw.header);
    }
    else if (parts.length === 2 && options.headless) {

        const headless = exports.headless(options);
        artifacts.token = `${headless.raw}.${token}`;
        artifacts.raw = { header: headless.raw, payload: parts[0], signature: parts[1] };
        artifacts.decoded.header = headless.decoded;
    }
    else {
        throw internals.error('Invalid token structure', artifacts);
    }

    for (const part of internals.parts) {
        if (!internals.partRx.test(artifacts.raw[part])) {
            throw internals.error(`Invalid token ${part} part`, artifacts);
        }
    }

    artifacts.decoded.payload = internals.b64decode(artifacts.raw.payload);
    artifacts.decoded.signature = artifacts.raw.signature;

    const header = artifacts.decoded.header;
    if (!header) {
        throw internals.error('Invalid token missing header', artifacts);
    }

    const parsed = Bourne.safeParse(artifacts.decoded.payload);
    if (!parsed ||
        typeof parsed !== 'object' ||
        Array.isArray(parsed)) {

        throw internals.error('Invalid token payload', artifacts);
    }

    artifacts.decoded.payload = parsed;

    if (!artifacts.decoded.header.alg) {
        throw internals.error('Token header missing alg attribute', artifacts);
    }

    return artifacts;
};


exports.verify = function (artifacts, secret, options = {}) {

    exports.verifySignature(artifacts, secret);
    exports.verifyPayload(artifacts, options);
};


exports.verifySignature = function ({ decoded, raw }, secret) {

    const { key, algorithm } = internals.key(decoded, secret);
    if (!Crypto.verify(raw, algorithm, key)) {
        throw new Error('Invalid token signature');
    }
};


exports.verifyPayload = function ({ decoded }, options = {}) {

    const nowSec = internals.tsSecs(options.now);
    const skewSec = options.timeSkewSec ?? 0;
    const payload = decoded.payload;

    // Expiration and max age

    exports.verifyTime({ decoded }, options, nowSec);

    // Audience

    internals.audiance(payload.aud, options.aud);

    // Properties

    internals.match('iss', payload, options);
    internals.match('sub', payload, options);
    internals.match('jti', payload, options);
    internals.match('nonce', payload, options);

    // Not before

    if (options.nbf !== false &&
        payload.nbf !== undefined) {

        if (typeof payload.nbf !== 'number') {
            throw new Error('Invalid payload nbf value');
        }

        if (payload.nbf > nowSec + skewSec) {
            throw new Error('Token not yet active');
        }
    }
};


exports.verifyTime = function ({ decoded }, options = {}, _nowSec = null) {

    const nowSec = _nowSec ?? internals.tsSecs(options.now);
    const skewSec = options.timeSkewSec ?? 0;
    const payload = decoded.payload;

    // Expiration

    if (options.exp !== false &&
        payload.exp !== undefined) {

        if (typeof payload.exp !== 'number') {
            throw new Error('Invalid payload exp value');
        }

        if (payload.exp <= nowSec - skewSec) {
            throw new Error('Token expired');
        }
    }

    // Max age

    if (options.maxAgeSec) {
        if (!payload.iat ||
            typeof payload.iat !== 'number') {

            throw new Error('Missing or invalid payload iat value');
        }

        if (nowSec - payload.iat - skewSec > options.maxAgeSec) {
            throw new Error('Token maximum age exceeded');
        }
    }
};


exports.headless = function (options) {

    const headless = options.headless;
    if (!headless) {
        return null;
    }

    if (typeof headless === 'object') {
        if (headless[internals.headless]) {
            return headless;
        }

        return {
            [internals.headless]: true,
            raw: Buffer.from(JSON.stringify(headless)).toString('base64'),
            decoded: headless
        };
    }

    return {
        [internals.headless]: true,
        raw: headless,
        decoded: internals.b64parse(headless)
    };
};


internals.error = function (message, artifacts) {

    const error = new Error(message);
    error.artifacts = artifacts;
    return error;
};


internals.b64decode = function (string) {

    return Buffer.from(string, 'base64').toString();
};


internals.b64parse = function (string) {

    return Bourne.safeParse(internals.b64decode(string));
};


internals.key = function (decoded, secret) {

    const { key, algorithms } = internals.secret(secret);
    if (!algorithms.includes(decoded.header.alg)) {
        throw new Error('Unsupported algorithm');
    }

    return { key, algorithm: decoded.header.alg };
};


internals.secret = function (secret) {

    const set = typeof secret === 'string' || Buffer.isBuffer(secret) ? { key: secret } : secret;

    return {
        key: set.key,
        algorithms: set.algorithm ? [set.algorithm] : set.algorithms || Keys.keyAlgorithms(set.key)
    };
};


internals.audiance = function (aud, audiences) {

    if (!audiences) {
        return;
    }

    if (aud === undefined) {
        throw new Error('Token missing payload aud value');
    }

    const auds = Array.isArray(aud) ? aud : [aud];
    audiences = Array.isArray(audiences) ? audiences : [audiences];

    for (const compare of auds) {
        for (const match of audiences) {
            if (typeof match === 'string') {
                if (compare === match) {
                    return;
                }
            }
            else {
                if (match.test(compare)) {
                    return;
                }
            }
        }
    }

    throw new Error('Token audience is not allowed');
};


internals.match = function (type, payload, options) {

    const matchTo = options[type];
    if (!matchTo) {
        return;
    }

    const value = payload[type];
    if (value === undefined) {
        throw new Error(`Token missing payload ${type} value`);
    }

    if (Array.isArray(matchTo) && matchTo.includes(value) ||
        matchTo === value) {

        return;
    }

    throw new Error(`Token payload ${type} value not allowed`);
};


internals.tsSecs = function (ts) {

    return Math.floor((ts ?? Date.now()) / 1000);
};

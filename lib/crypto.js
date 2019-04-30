'use strict';

const Crypto = require('crypto');

const Cryptiles = require('@hapi/cryptiles');
const EcdsaSigFormatter = require('ecdsa-sig-formatter');

const Utils = require('./utils');


const internals = {
    algorithms: {
        RS256: 'RSA-SHA256',
        RS384: 'RSA-SHA384',
        RS512: 'RSA-SHA512',

        PS256: 'RSA-SHA256',
        PS384: 'RSA-SHA384',
        PS512: 'RSA-SHA512',

        ES256: 'RSA-SHA256',
        ES384: 'RSA-SHA384',
        ES512: 'RSA-SHA512',

        HS256: 'sha256',
        HS384: 'sha384',
        HS512: 'sha512'
    }
};


exports.generate = function (value, algorithm, key) {

    algorithm = algorithm.toUpperCase();

    if (algorithm === 'NONE') {
        return '';
    }

    const algo = internals.algorithms[algorithm];
    if (!algo) {
        throw new Error('Unsupported algorithm');
    }

    switch (algorithm) {
        case 'RS256':
        case 'RS384':
        case 'RS512': {

            const signer = Crypto.createSign(algo);
            signer.update(value);
            const sig = signer.sign(key, 'base64');
            return internals.b64urlEncode(sig);
        }

        case 'PS256':
        case 'PS384':
        case 'PS512': {

            const signer = Crypto.createSign(algo);
            signer.update(value);
            const sig = signer.sign({ key, padding: Crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: Crypto.constants.RSA_PSS_SALTLEN_DIGEST }, 'base64');
            return internals.b64urlEncode(sig);
        }

        case 'ES256':
        case 'ES384':
        case 'ES512': {

            const signer = Crypto.createSign(algo);
            signer.update(value);
            const sig = signer.sign(key, 'base64');
            return EcdsaSigFormatter.derToJose(sig, algorithm);
        }

        case 'HS256':
        case 'HS384':
        case 'HS512': {

            const hmac = Crypto.createHmac(algo, key);
            hmac.update(value);
            const digest = hmac.digest('base64');
            return internals.b64urlEncode(digest);
        }
    }
};


exports.verify = function (raw, algorithm, key) {

    algorithm = algorithm.toUpperCase();

    if (algorithm === 'NONE') {
        return raw.signature === '';
    }

    const algo = internals.algorithms[algorithm];
    if (!algo) {
        throw new Error('Unsupported algorithm');
    }

    const value = `${raw.header}.${raw.payload}`;
    const signature = raw.signature;

    switch (algorithm) {
        case 'RS256':
        case 'RS384':
        case 'RS512': {

            const verifier = Crypto.createVerify(algo);
            verifier.update(value);
            return verifier.verify(key, internals.b64urlDecode(signature), 'base64');
        }

        case 'PS256':
        case 'PS384':
        case 'PS512': {

            const verifier = Crypto.createVerify(algo);
            verifier.update(value);
            return verifier.verify({ key, padding: Crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: Crypto.constants.RSA_PSS_SALTLEN_DIGEST }, internals.b64urlDecode(signature), 'base64');
        }

        case 'ES256':
        case 'ES384':
        case 'ES512': {

            const sig = EcdsaSigFormatter.joseToDer(signature, algorithm).toString('base64');
            const verifier = Crypto.createVerify(algo);
            verifier.update(value);
            return verifier.verify(key, internals.b64urlDecode(sig), 'base64');
        }

        case 'HS256':
        case 'HS384':
        case 'HS512': {

            const compare = exports.generate(value, algorithm, key);
            return Cryptiles.fixedTimeComparison(signature, compare);
        }
    }
};


internals.b64urlEncode = function (b64) {

    return b64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};


internals.b64urlDecode = function (b64url) {

    b64url = b64url.toString();

    const padding = 4 - b64url.length % 4;
    if (padding !== 4) {
        for (let i = 0; i < padding; ++i) {
            b64url += '=';
        }
    }

    return b64url.replace(/\-/g, '+').replace(/_/g, '/');
};


exports.certToPEM = function (cert) {

    return `-----BEGIN CERTIFICATE-----\n${internals.chop(cert)}\n-----END CERTIFICATE-----\n`;
};


exports.rsaPublicKeyToPEM = function (modulusB64, exponentB64) {

    const modulusHex = internals.prepadSigned(Buffer.from(modulusB64, 'base64').toString('hex'));
    const exponentHex = internals.prepadSigned(Buffer.from(exponentB64, 'base64').toString('hex'));

    const modlen = modulusHex.length / 2;
    const explen = exponentHex.length / 2;

    const encodedModlen = internals.encodeLengthHex(modlen);
    const encodedExplen = internals.encodeLengthHex(explen);

    const encodedPubkey = '30' +
        internals.encodeLengthHex(modlen + explen + encodedModlen.length / 2 + encodedExplen.length / 2 + 2) +
        '02' + encodedModlen + modulusHex +
        '02' + encodedExplen + exponentHex;

    const der = internals.chop(Buffer.from(encodedPubkey, 'hex').toString('base64'));
    return `-----BEGIN RSA PUBLIC KEY-----\n${der}\n-----END RSA PUBLIC KEY-----\n`;
};


internals.prepadSigned = function (hexStr) {

    const msb = hexStr[0];
    if (msb > '7') {
        return `00${hexStr}`;
    }

    return hexStr;
};


internals.encodeLengthHex = function (n) {

    if (n <= 127) {
        return Utils.toHex(n);
    }

    const nHex = Utils.toHex(n);
    const lengthOfLengthByte = 128 + nHex.length / 2;
    return Utils.toHex(lengthOfLengthByte) + nHex;
};


internals.chop = function (cert) {

    return cert.match(/.{1,64}/g).join('\n');
};

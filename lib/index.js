'use strict';

const Crypto = require('./crypto');
const Plugin = require('./plugin');
const Token = require('./token');
const Utils = require('./utils');


exports.plugin = Plugin.plugin;

exports.token = {
    generate: Token.generate,
    decode: Token.decode,
    verify: Token.verify,

    verifySignature: Token.verifySignature,
    verifyPayload: Token.verifyPayload,
    verifyTime: Token.verifyTime,

    signature: {
        generate: Crypto.generate,
        verify: Crypto.verify
    }
};

exports.crypto = {
    rsaPublicKeyToPEM: Crypto.rsaPublicKeyToPEM
};

exports.utils = Utils;

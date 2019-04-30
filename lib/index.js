'use strict';

const Crypto = require('./crypto');
const Plugin = require('./plugin');
const Token = require('./token');
const Utils = require('./utils');


const internals = {};


module.exports = {
    plugin: Plugin.plugin,

    token: {
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
    },

    crypto: {
        rsaPublicKeyToPEM: Crypto.rsaPublicKeyToPEM
    },

    utils: Utils
};

'use strict';

const B64 = require('@hapi/b64');
const Joi = require('joi');


const internals = {};


exports.b64stringify = function (obj) {

    return B64.base64urlEncode(JSON.stringify(obj), 'utf-8');
};


exports.toHex = function (number) {

    const nstr = number.toString(16);
    if (nstr.length % 2) {
        return `0${nstr}`;
    }

    return nstr;
};

// Refer for header name pattern reference https://github.com/nodejs/node/blob/7ef069e483e015a803660125cdbfa81ddfa0357b/lib/_http_common.js#L203

exports.validHttpTokenSchema = Joi.string().pattern(/^[\^_`a-zA-Z\-0-9!#$%&'*+.|~]+$/);

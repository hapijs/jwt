'use strict';

const B64 = require('@hapi/b64');


const internals = {};


exports.b64stringify = function (obj) {

    return B64.base64urlEncode(JSON.stringify(obj));
};


exports.toHex = function (number) {

    const nstr = number.toString(16);
    if (nstr.length % 2) {
        return `0${nstr}`;
    }

    return nstr;
};

'use strict';

const Code = require('@hapi/code');
const Jwt = require('..');
const Lab = require('@hapi/lab');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Utils', () => {

    describe('toHex()', () => {

        it('converts numbers to hex string', () => {

            expect(Jwt.utils.toHex(1)).to.equal('01');
            expect(Jwt.utils.toHex(100001)).to.equal('0186a1');
            expect(Jwt.utils.toHex(4040404)).to.equal('3da6d4');
        });
    });
});

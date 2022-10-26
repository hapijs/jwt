'use strict';

const Code = require('@hapi/code');
const Jwt = require('..');
const Lab = require('@hapi/lab');

const Mock = require('./mock');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Crypto', () => {

    describe('RSA', () => {

        const algorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
        for (const algorithm of algorithms) {
            it(`supports ${algorithm}`, () => {

                const header = 'abc';
                const payload = '123';
                const value = `${header}.${payload}`;

                const pair = Mock.pair();
                const signature = Jwt.token.signature.generate(value, algorithm, pair.private);
                expect(Jwt.token.signature.verify({ header, payload, signature }, algorithm, pair.public)).to.be.true();
            });
        }
    });

    describe('EC', () => {

        const algorithms = ['ES256', 'ES384', 'ES512'];
        for (const algorithm of algorithms) {
            it(`supports ${algorithm}`, () => {

                const header = 'abc';
                const payload = '123';
                const value = `${header}.${payload}`;

                const pair = Mock.pair('ec', algorithm.slice(2));
                const signature = Jwt.token.signature.generate(value, algorithm, pair.private);
                expect(Jwt.token.signature.verify({ header, payload, signature }, algorithm, pair.public)).to.be.true();
            });
        }
    });

    describe('EdDSA', () => {

        const alg = 'EdDSA';
        const curves = ['ed25519', 'ed448'];
        for (const crv of curves) {
            it(`supports ${alg} ${crv}`, () => {

                const header = 'abc';
                const payload = '123';
                const value = `${header}.${payload}`;

                const pair = Mock.pair(alg, crv);
                const signature = Jwt.token.signature.generate(value, alg, pair.private);
                expect(Jwt.token.signature.verify({ header, payload, signature }, alg, pair.public)).to.be.true();
            });
        }
    });


    describe('generate()', () => {

        it('errors on unsupported algorithm', () => {

            expect(() => Jwt.token.signature.generate('abc', 'unknown', 'secret')).to.throw('Unsupported algorithm');
        });
    });

    describe('verify()', () => {

        it('errors on unsupported algorithm', () => {

            expect(() => Jwt.token.signature.verify({}, 'unknown', 'secret')).to.throw('Unsupported algorithm');
        });
    });

    describe('rsaPublicKeyToPEM()', () => {

        it('converts public key to PEM', () => {

            const e = 'AQAB';
            const n = 'ALmBQblv13+ReieM3zRFTSvm+TUmF/o465Y3tKijFUkjTdyYyOeY7jQoau6Af917/TJtEC4XtQyBBY0GZU7KPN0s9a+h4/lLfqNTAfPcWjxm7aoWOtWbqRUpqlm38knwm6BZ2zyc/9rsvfNXWx6fgs47W9n6i1RyVuAHkuj4pMmstiLWDmmhrOH8Sz7L1iZwkwPU6AczILiHW0PJLlu7a0lVeYAB0FOETXu9iDPXhi4z6m35UIhEa343S7fp1z4k+R9oxdr5n92A1nNNV+6Kkpi+s8E+ukiFcbEJkCLvGt8uPxQvqUJVavHtHDX2aqVJnORydluTnPTlhU+aJ9F9JQs=';

            expect(Jwt.crypto.rsaPublicKeyToPEM(n, e)).to.equal('-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAuYFBuW/Xf5F6J4zfNEVNK+b5NSYX+jjrlje0qKMVSSNN3JjI55ju\nNChq7oB/3Xv9Mm0QLhe1DIEFjQZlTso83Sz1r6Hj+Ut+o1MB89xaPGbtqhY61Zup\nFSmqWbfySfCboFnbPJz/2uy981dbHp+Czjtb2fqLVHJW4AeS6Pikyay2ItYOaaGs\n4fxLPsvWJnCTA9ToBzMguIdbQ8kuW7trSVV5gAHQU4RNe72IM9eGLjPqbflQiERr\nfjdLt+nXPiT5H2jF2vmf3YDWc01X7oqSmL6zwT66SIVxsQmQIu8a3y4/FC+pQlVq\n8e0cNfZqpUmc5HJ2W5Oc9OWFT5on0X0lCwIDAQAB\n-----END RSA PUBLIC KEY-----\n');
        });

        it('converts public key to PEM (letter msb)', () => {

            const e = 'AQAB';
            const n = 's4W7xjkQZP3OwG7PfRgcYKn8eRYXHiz1iK503fS-K2FZo-Ublwwa2xFZWpsUU_jtoVCwIkaqZuo6xoKtlMYXXvfVHGuKBHEBVn8b8x_57BQWz1d0KdrNXxuMvtFe6RzMqiMqzqZrzae4UqVCkYqcR9gQx66Ehq7hPmCxJCkg7ajo7fu6E7dPd34KH2HSYRsaaEA_BcKTeb9H1XE_qEKjog68wUU9Ekfl3FBIRN-1Ah_BoktGFoXyi_jt0-L0-gKcL1BLmUlGzMusvRbjI_0-qj-mc0utGdRjY-xIN2yBj8vl4DODO-wMwfp-cqZbCd9TENyHaTb8iA27s-73L3ExOQ';

            expect(Jwt.crypto.rsaPublicKeyToPEM(n, e)).to.equal('-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAs4W7xjkQZP3OwG7PfRgcYKn8eRYXHiz1iK503fS+K2FZo+Ublwwa\n2xFZWpsUU/jtoVCwIkaqZuo6xoKtlMYXXvfVHGuKBHEBVn8b8x/57BQWz1d0KdrN\nXxuMvtFe6RzMqiMqzqZrzae4UqVCkYqcR9gQx66Ehq7hPmCxJCkg7ajo7fu6E7dP\nd34KH2HSYRsaaEA/BcKTeb9H1XE/qEKjog68wUU9Ekfl3FBIRN+1Ah/BoktGFoXy\ni/jt0+L0+gKcL1BLmUlGzMusvRbjI/0+qj+mc0utGdRjY+xIN2yBj8vl4DODO+wM\nwfp+cqZbCd9TENyHaTb8iA27s+73L3ExOQIDAQAB\n-----END RSA PUBLIC KEY-----\n');
        });
    });
});

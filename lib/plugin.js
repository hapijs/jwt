'use strict';

const Boom = require('@hapi/boom');
const CatboxObject = require('@hapi/catbox-object');
const Hoek = require('@hapi/hoek');
const Joi = require('joi');

const Crypto = require('./crypto');
const Keys = require('./keys');
const Token = require('./token');
const Utils = require('./utils');


const internals = {};


exports.plugin = {
    pkg: require('../package.json'),
    requirements: {
        hapi: '>=20.0.0'
    },
    register: function (server) {

        server.expose('_providers', []);
        server.expose('_caching', false);
        server.expose('_cacheName', '@hapi/jwt');

        server.ext('onPreStart', internals.onPreStart);

        server.auth.scheme('jwt', internals.implementation);
    }
};


internals.onPreStart = function (server) {

    const providers = server.plugins.jwt._providers;

    const pendings = [];
    for (let i = 0; i < providers.length; ++i) {
        const provider = providers[i];
        pendings.push(provider.initialize(`s${i}`));
    }

    return Promise.all(pendings);
};


internals.schema = {
    algorithms: Joi.array()
        .items(Joi.string().valid(...Keys.supportedAlgorithms))
        .min(1)
        .single()
};


internals.schema.strategy = Joi.object({

    cache: Joi.object({
        segment: Joi.forbidden(),
        generateFunc: Joi.forbidden(),
        cache: Joi.forbidden(),
        shared: Joi.forbidden()
    })
        .unknown()
        .default({
            expiresIn: 7 * 24 * 60 * 60 * 1000,                 // 1 weeks
            staleIn: 60 * 60 * 1000,                            // 1 hour
            staleTimeout: 500,                                  // 500 milliseconds
            generateTimeout: 2 * 60 * 1000                      // 2 minutes
        }),

    cookieName: Utils.validHttpTokenSchema
        .optional()
        .messages({
            'string.pattern.base':
                'Cookie name cannot start or end with special characters. Valid characters in cookie name are _, -, numbers and alphabets'
        }),

    headerName: Joi.any().when('cookieName', {
        is: Joi.exist(),
        then: Joi.string().forbidden().messages({ 'any.unknown': 'headerName not allowed when cookieName is specified' }),
        otherwise: Utils.validHttpTokenSchema.optional()
            .default('authorization')
            .messages({
                'string.pattern.base': 'Header name must be a valid header name following https://tools.ietf.org/html/rfc7230#section-3.2.6'
            })
    }),

    headless: [Joi.string(), Joi.object({ alg: Joi.string().valid(...Keys.supportedAlgorithms).required(), typ: Joi.valid('JWT') }).unknown()],

    httpAuthScheme: Joi.string().default('Bearer'),

    keys: Joi.array().
        items(
            Joi.string(),
            Joi.binary(),
            Joi.func(),
            {
                key: Joi.valid('').default(''),
                algorithms: Joi.array().items(Joi.valid('none')).length(1).single().required(),
                kid: Joi.string()
            },
            {
                key: Joi.alternatives([Joi.string(), Joi.binary()]).required(),
                algorithms: internals.schema.algorithms,
                kid: Joi.string()
            },
            {
                uri: Joi.string().uri().required(),
                rejectUnauthorized: Joi.boolean().default(true),
                headers: Joi.object().pattern(/.+/, Joi.string()),
                algorithms: internals.schema.algorithms
            }
        )
        .min(1)
        .single()
        .when('verify', { is: false, otherwise: Joi.required() }),

    unauthorizedAttributes: Joi.object().pattern(/.+/, Joi.string().allow(null, '')),

    validate: Joi.func().allow(false).required(),

    verify: Joi.object({
        aud: Joi.array().items(Joi.string(), Joi.object().instance(RegExp)).min(1).single().allow(false).required(),
        exp: Joi.boolean().default(true),
        iss: Joi.array().items(Joi.string()).min(1).single().allow(false).required(),
        nbf: Joi.boolean().default(true),
        sub: Joi.array().items(Joi.string()).min(1).single().allow(false).required(),

        maxAgeSec: Joi.number().integer().min(0).default(0),
        timeSkewSec: Joi.number().integer().min(0).default(0)
    })
        .when('.validate', { is: Joi.not(false), then: Joi.allow(false) })
        .required()
});


internals.implementation = function (server, options) {

    Hoek.assert(options, 'JWT authentication options missing');

    const settings = Joi.attempt(Hoek.clone(options), internals.schema.strategy);
    settings.headless = Token.headless(settings);

    const unauthorized = (message = null) => Boom.unauthorized(message, settings.httpAuthScheme, settings.unauthorizedAttributes);
    const missing = unauthorized();

    const provider = new Keys(server, settings);

    if (provider.hasJwks &&
        !server.plugins.jwt._caching) {

        server.plugins.jwt._caching = true;
        server.cache.provision({ provider: CatboxObject.Engine, name: server.plugins.jwt._cacheName });
    }

    return {
        authenticate: async function (request, h) {

            const result = { credentials: {} };

            // Extract token

            const token = internals.token(request, settings, missing, unauthorized);

            // Decode token

            try {
                result.artifacts = Token.decode(token, settings);
            }
            catch (err) {
                result.artifacts = err.artifacts;
                return h.unauthenticated(unauthorized(err.message), result);
            }

            // Obtain keys

            await provider.assign(result.artifacts, request);
            if (!result.artifacts.keys) {
                return h.unauthenticated(unauthorized(''), result);
            }

            // Verify token

            if (settings.verify) {
                try {
                    Token.verifyPayload(result.artifacts, settings.verify);
                }
                catch (err) {
                    return h.unauthenticated(unauthorized(err.message), result);
                }

                let valid = false;
                for (const key of result.artifacts.keys) {
                    if (Crypto.verify(result.artifacts.raw, key.algorithm, key.key)) {
                        valid = true;
                        break;
                    }
                }

                if (!valid) {
                    return h.unauthenticated(unauthorized('Invalid token signature'), result);
                }
            }

            result.credentials = result.artifacts.decoded.payload;

            // Validate token

            if (settings.validate) {
                try {
                    var { isValid, credentials, response } = await settings.validate(result.artifacts, request, h);
                }
                catch (err) {
                    result.error = err;
                    return h.unauthenticated(unauthorized(err.message), result);
                }

                if (response !== undefined) {
                    return h.response(response).takeover();
                }

                if (credentials) {
                    result.credentials = credentials;
                }

                if (!isValid) {
                    return h.unauthenticated(unauthorized('Invalid credentials'), result);
                }
            }

            return h.authenticated(result);
        },

        verify: function (auth) {

            if (settings.verify) {
                Token.verifyTime(auth.artifacts, settings.verify);
            }
        }
    };
};


internals.token = function (request, settings, missing, unauthorized) {

    // Read the authentication token from the source depending upon the setting

    let authorization = null;

    if (settings.headerName) {
        authorization = request.headers[settings.headerName];
    }
    else {
        authorization = request.state[settings.cookieName];
    }

    if (!authorization) {
        throw missing;
    }

    // Authorization header will be like <Scheme> <Token>

    if (settings.headerName) {
        const parts = authorization.split(/\s+/);
        if (parts[0].toLowerCase() !== settings.httpAuthScheme.toLowerCase()) {
            throw missing;
        }

        if (parts.length !== 2) {
            throw unauthorized('Bad HTTP authentication header format');
        }

        const token = parts[1];
        if (!token) {
            throw missing;
        }

        return token;
    }

    return authorization;
};

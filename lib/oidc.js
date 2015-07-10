'use strict';

/**
 * Module dependencies
 */

var _promiseFactory = require('es6-promise').Promise;
var r = require('jsrsasign');
var utility = require('./utility.js');
var Cookies = require('cookies');

var exports = module.exports = {
    _settings: {},

    init: function(req, res, settings) {
        this._settings = settings || {};
        var that = this;

        if (!this._settings.request_state_key) {
            this._settings.request_state_key = "OidcClient.request_state";
        }

        if (!this._settings.request_state_store) {
            this._settings.request_state_store = new Cookies(req, res);
        }

        if (typeof this._settings.load_user_profile === 'undefined') {
            this._settings.load_user_profile = true;
        }

        if (typeof this._settings.filter_protocol_claims === 'undefined') {
            this._settings.filter_protocol_claims = true;
        }

        if (this._settings.authority && this._settings.authority.indexOf('.well-known/openid-configuration') < 0) {
            if (this._settings.authority[this._settings.authority.length - 1] !== '/') {
                this._settings.authority += '/';
            }
            this._settings.authority += '.well-known/openid-configuration';
        }

        if (!this._settings.response_type) {
            this._settings.response_type = "id_token token";
        }

        Object.defineProperty(this, "isOidc", {
            get: function () {
                if (that._settings.response_type) {
                    var result = this._settings.response_type.split(/\s+/g).filter(function (item) {
                        return item === "id_token";
                    });
                    return !!(result[0]);
                }
                return false;
            }
        });

        Object.defineProperty(this, "isOAuth", {
            get: function () {
                if (that._settings.response_type) {
                    var result = this._settings.response_type.split(/\s+/g).filter(function (item) {
                        return item === "token";
                    });
                    return !!(result[0]);
                }
                return false;
            }
        });
    },

    loadMetadataAsync: function () {
        utility.log("OIDC.loadMetadataAsync");

        var settings = this._settings;

        if (settings.metadata) {
            return _promiseFactory.resolve(settings.metadata);
        }

        if (!settings.authority) {
            return this.error("No authority configured");
        }

        return utility.getJson(settings.authority)
            .then(function (metadata) {
                settings.metadata = metadata;
                return metadata;
            }, function (err) {
                return this.error("Failed to load metadata (" + err.message + ")");
            });
    },

    loadX509SigningKeyAsync: function () {
        utility.log("OIDC.loadX509SigningKeyAsync");

        var settings = this._settings;

        function getKeyAsync(jwks) {
            if (!jwks.keys || !jwks.keys.length) {
                return this.error("Signing keys empty");
            }

            var key = jwks.keys[0];
            if (key.kty !== "RSA") {
                return this.error("Signing key not RSA");
            }

            if (!key.x5c || !key.x5c.length) {
                return this.error("RSA keys empty");
            }

            return _promiseFactory.resolve(key.x5c[0]);
        }

        if (settings.jwks) {
            return getKeyAsync(settings.jwks);
        }

        return this.loadMetadataAsync().then(function (metadata) {
            if (!metadata.jwks_uri) {
                return this.error("Metadata does not contain jwks_uri");
            }

            return utility.getJson(metadata.jwks_uri).then(function (jwks) {
                settings.jwks = jwks;
                return getKeyAsync(jwks);
            }, function (err) {
                return this.error("Failed to load signing keys (" + err.message + ")");
            });
        });
    },

    loadUserProfile: function (access_token) {
        utility.log("OIDC.loadUserProfile");

        return this.loadMetadataAsync().then(function (metadata) {

            if (!metadata.userinfo_endpoint) {
                return _promiseFactory.reject(Error("Metadata does not contain userinfo_endpoint"));
            }

            return utility.getJson(metadata.userinfo_endpoint, access_token);
        });
    },

    loadAuthorizationEndpoint: function () {
        utility.log("OIDC.loadAuthorizationEndpoint");

        if (this._settings.authorization_endpoint) {
            return _promiseFactory.resolve(this._settings.authorization_endpoint);
        }

        if (!this._settings.authority) {
            return this.error("No authorization_endpoint configured");
        }

        return this.loadMetadataAsync().then(function (metadata) {
            if (!metadata.authorization_endpoint) {
                return this.error("Metadata does not contain authorization_endpoint");
            }

            return metadata.authorization_endpoint;
        });
    },

    createTokenRequestAsync: function () {
        utility.log("OIDC.createTokenRequestAsync");

        var client = this;
        var settings = client._settings;

        return client.loadAuthorizationEndpoint().then(function (authorization_endpoint) {

            var state = utility.rand();
            var url = authorization_endpoint + "?state=" + encodeURIComponent(state);

            if (client.isOidc) {
                var nonce = utility.rand();
                url += "&nonce=" + encodeURIComponent(nonce);
            }

            var required = ["client_id", "redirect_uri", "response_type", "scope"];
            required.forEach(function (key) {
                var value = settings[key];
                if (value) {
                    url += "&" + key + "=" + encodeURIComponent(value);
                }
            });

            var optional = ["prompt", "display", "max_age", "ui_locales", "id_token_hint", "login_hint", "acr_values"];
            optional.forEach(function (key) {
                var value = settings[key];
                if (value) {
                    url += "&" + key + "=" + encodeURIComponent(value);
                }
            });

            var request_state = {
                oidc: client.isOidc,
                oauth: client.isOAuth,
                state: state
            };

            if (nonce) {
                request_state["nonce"] = nonce;
            }

            settings.request_state_store.set(settings.request_state_key, JSON.stringify(request_state));

            return {
                request_state: request_state,
                url: url
            };
        });
    },

    createLogoutRequestAsync: function (id_token_hint) {
        utility.log("OIDC.createLogoutRequestAsync");

        var settings = this._settings;
        return this.loadMetadataAsync().then(function (metadata) {
            if (!metadata.end_session_endpoint) {
                return this.error("No end_session_endpoint in metadata");
            }

            var url = metadata.end_session_endpoint;
            if (id_token_hint && settings.post_logout_redirect_uri) {
                url += "?post_logout_redirect_uri=" + encodeURIComponent(settings.post_logout_redirect_uri);
                url += "&id_token_hint=" + encodeURIComponent(id_token_hint);
            }
            return url;
        });
    },

    validateIdTokenAsync: function (id_token, nonce, access_token) {
        utility.log("OIDC.validateIdTokenAsync");

        var client = this;
        var settings = client._settings;

        return client.loadX509SigningKeyAsync().then(function (cert) {

            var jws = new KJUR.jws.JWS();
            if (jws.verifyJWSByPemX509Cert(id_token, cert)) {
                var id_token_contents = JSON.parse(jws.parsedJWS.payloadS);

                if (nonce !== id_token_contents.nonce) {
                    return this.error("Invalid nonce");
                }

                return client.loadMetadataAsync().then(function (metadata) {

                    if (id_token_contents.iss !== metadata.issuer) {
                        return this.error("Invalid issuer");
                    }

                    if (id_token_contents.aud !== settings.client_id) {
                        return this.error("Invalid audience");
                    }

                    var now = parseInt(Date.now() / 1000);

                    // accept tokens issues up to 5 mins ago
                    var diff = now - id_token_contents.iat;
                    if (diff > (5 * 60)) {
                        return this.error("Token issued too long ago");
                    }

                    if (id_token_contents.exp < now) {
                        return this.error("Token expired");
                    }

                    if (access_token && settings.load_user_profile) {
                        // if we have an access token, then call user info endpoint
                        return client.loadUserProfile(access_token, id_token_contents).then(function (profile) {
                            return utility.copy(profile, id_token_contents);
                        });
                    }
                    else {
                        // no access token, so we have all our claims
                        return id_token_contents;
                    }

                });
            }
            else {
                return this.error("JWT failed to validate");
            }
        });
    },

    validateAccessTokenAsync: function (id_token_contents, access_token) {
        utility.log("OIDC.validateAccessTokenAsync");

        if (!id_token_contents.at_hash) {
            return this.error("No at_hash in id_token");
        }

        var hash = KJUR.crypto.Util.sha256(access_token);
        var left = hash.substr(0, hash.length / 2);
        var left_b64u = hextob64u(left);

        if (left_b64u !== id_token_contents.at_hash) {
            return this.error("at_hash failed to validate");
        }

        return _promiseFactory.resolve();
    },

    validateIdTokenAndAccessTokenAsync: function (id_token, nonce, access_token) {
        utility.log("OIDC.validateIdTokenAndAccessTokenAsync");

        var client = this;

        return client.validateIdTokenAsync(id_token, nonce, access_token).then(function (id_token_contents) {

            return client.validateAccessTokenAsync(id_token_contents, access_token).then(function () {

                return id_token_contents;

            });

        });
    },

    processResponseAsync: function (queryString) {
        utility.log("OIDC.processResponseAsync");

        var client = this;
        var settings = client._settings;

        var request_state = settings.request_state_store.get(settings.request_state_key);
        settings.request_state_store.remove(settings.request_state_key);

        if (!request_state) {
            return this.error("No request state loaded");
        }

        request_state = JSON.parse(request_state);
        if (!request_state) {
            return this.error("No request state loaded");
        }

        if (!request_state.state) {
            return this.error("No state loaded");
        }

        var result = utility.parseOidcResult(queryString);
        if (!result) {
            return this.error("No OIDC response");
        }

        if (result.error) {
            return this.error(result.error);
        }

        if (result.state !== request_state.state) {
            return this.error("Invalid state");
        }

        if (request_state.oidc) {
            if (!result.id_token) {
                return this.error("No identity token");
            }

            if (!request_state.nonce) {
                return this.error("No nonce loaded");
            }
        }

        if (request_state.oauth) {
            if (!result.access_token) {
                return this.error("No access token");
            }

            if (!result.token_type || result.token_type.toLowerCase() !== "bearer") {
                return this.error("Invalid token type");
            }

            if (!result.expires_in) {
                return this.error("No token expiration");
            }
        }

        var promise = _promiseFactory.resolve();
        if (request_state.oidc && request_state.oauth) {
            promise = client.validateIdTokenAndAccessTokenAsync(result.id_token, request_state.nonce, result.access_token);
        }
        else if (request_state.oidc) {
            promise = client.validateIdTokenAsync(result.id_token, request_state.nonce);
        }

        return promise.then(function (profile) {
            if (profile && settings.filter_protocol_claims) {
                var remove = ["nonce", "at_hash", "iat", "nbf", "exp", "aud", "iss", "idp"];
                remove.forEach(function (key) {
                    delete profile[key];
                });
            }

            return {
                profile: profile,
                id_token: result.id_token,
                access_token: result.access_token,
                expires_in: result.expires_in,
                scope: result.scope,
                session_state: result.session_state
            };
        });
    },

    error: function(message) {
        utility.error(_promiseFactory, message);
    }
};
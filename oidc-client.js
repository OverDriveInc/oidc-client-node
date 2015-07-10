﻿
function OidcClient(settings) {
    this._settings = settings || {};

    if (!this._settings.request_state_key) {
        this._settings.request_state_key = "OidcClient.request_state";
    }

    if (!this._settings.request_state_store) {
        this._settings.request_state_store = window.localStorage;
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
            if (this._settings.response_type) {
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
            if (this._settings.response_type) {
                var result = this._settings.response_type.split(/\s+/g).filter(function (item) {
                    return item === "token";
                });
                return !!(result[0]);
            }
            return false;
        }
    });
}

OidcClient.prototype.loadMetadataAsync = function () {
    log("OidcClient.loadMetadataAsync");

    var settings = this._settings;

    if (settings.metadata) {
        return _promiseFactory.resolve(settings.metadata);
    }

    if (!settings.authority) {
        return error("No authority configured");
    }

    return getJson(settings.authority)
        .then(function (metadata) {
            settings.metadata = metadata;
            return metadata;
        }, function (err) {
            return error("Failed to load metadata (" + err.message + ")");
        });
};

OidcClient.prototype.loadX509SigningKeyAsync = function () {
    log("OidcClient.loadX509SigningKeyAsync");

    var settings = this._settings;

    function getKeyAsync(jwks) {
        if (!jwks.keys || !jwks.keys.length) {
            return error("Signing keys empty");
        }

        var key = jwks.keys[0];
        if (key.kty !== "RSA") {
            return error("Signing key not RSA");
        }

        if (!key.x5c || !key.x5c.length) {
            return error("RSA keys empty");
        }

        return _promiseFactory.resolve(key.x5c[0]);
    }

    if (settings.jwks) {
        return getKeyAsync(settings.jwks);
    }

    return this.loadMetadataAsync().then(function (metadata) {
        if (!metadata.jwks_uri) {
            return error("Metadata does not contain jwks_uri");
        }

        return getJson(metadata.jwks_uri).then(function (jwks) {
            settings.jwks = jwks;
            return getKeyAsync(jwks);
        }, function (err) {
            return error("Failed to load signing keys (" + err.message + ")");
        });
    });
};

OidcClient.prototype.loadUserProfile = function (access_token) {
    log("OidcClient.loadUserProfile");

    return this.loadMetadataAsync().then(function (metadata) {

        if (!metadata.userinfo_endpoint) {
            return _promiseFactory.reject(Error("Metadata does not contain userinfo_endpoint"));
        }

        return getJson(metadata.userinfo_endpoint, access_token);
    });
};

OidcClient.prototype.loadAuthorizationEndpoint = function () {
    log("OidcClient.loadAuthorizationEndpoint");

    if (this._settings.authorization_endpoint) {
        return _promiseFactory.resolve(this._settings.authorization_endpoint);
    }

    if (!this._settings.authority) {
        return error("No authorization_endpoint configured");
    }

    return this.loadMetadataAsync().then(function (metadata) {
        if (!metadata.authorization_endpoint) {
            return error("Metadata does not contain authorization_endpoint");
        }

        return metadata.authorization_endpoint;
    });
};

OidcClient.prototype.createTokenRequestAsync = function () {
    log("OidcClient.createTokenRequestAsync");

    var client = this;
    var settings = client._settings;

    return client.loadAuthorizationEndpoint().then(function (authorization_endpoint) {

        var state = rand();
        var url = authorization_endpoint + "?state=" + encodeURIComponent(state);

        if (client.isOidc) {
            var nonce = rand();
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

        settings.request_state_store.setItem(settings.request_state_key, JSON.stringify(request_state));

        return {
            request_state: request_state,
            url: url
        };
    });
}

OidcClient.prototype.createLogoutRequestAsync = function (id_token_hint) {
    log("OidcClient.createLogoutRequestAsync");

    var settings = this._settings;
    return this.loadMetadataAsync().then(function (metadata) {
        if (!metadata.end_session_endpoint) {
            return error("No end_session_endpoint in metadata");
        }

        var url = metadata.end_session_endpoint;
        if (id_token_hint && settings.post_logout_redirect_uri) {
            url += "?post_logout_redirect_uri=" + encodeURIComponent(settings.post_logout_redirect_uri);
            url += "&id_token_hint=" + encodeURIComponent(id_token_hint);
        }
        return url;
    });
}

OidcClient.prototype.validateIdTokenAsync = function (id_token, nonce, access_token) {
    log("OidcClient.validateIdTokenAsync");

    var client = this;
    var settings = client._settings;

    return client.loadX509SigningKeyAsync().then(function (cert) {

        var jws = new KJUR.jws.JWS();
        if (jws.verifyJWSByPemX509Cert(id_token, cert)) {
            var id_token_contents = JSON.parse(jws.parsedJWS.payloadS);

            if (nonce !== id_token_contents.nonce) {
                return error("Invalid nonce");
            }

            return client.loadMetadataAsync().then(function (metadata) {

                if (id_token_contents.iss !== metadata.issuer) {
                    return error("Invalid issuer");
                }

                if (id_token_contents.aud !== settings.client_id) {
                    return error("Invalid audience");
                }

                var now = parseInt(Date.now() / 1000);

                // accept tokens issues up to 5 mins ago
                var diff = now - id_token_contents.iat;
                if (diff > (5 * 60)) {
                    return error("Token issued too long ago");
                }

                if (id_token_contents.exp < now) {
                    return error("Token expired");
                }

                if (access_token && settings.load_user_profile) {
                    // if we have an access token, then call user info endpoint
                    return client.loadUserProfile(access_token, id_token_contents).then(function (profile) {
                        return copy(profile, id_token_contents);
                    });
                }
                else {
                    // no access token, so we have all our claims
                    return id_token_contents;
                }

            });
        }
        else {
            return error("JWT failed to validate");
        }

    });

};

OidcClient.prototype.validateAccessTokenAsync = function (id_token_contents, access_token) {
    log("OidcClient.validateAccessTokenAsync");

    if (!id_token_contents.at_hash) {
        return error("No at_hash in id_token");
    }

    var hash = KJUR.crypto.Util.sha256(access_token);
    var left = hash.substr(0, hash.length / 2);
    var left_b64u = hextob64u(left);

    if (left_b64u !== id_token_contents.at_hash) {
        return error("at_hash failed to validate");
    }

    return _promiseFactory.resolve();
};

OidcClient.prototype.validateIdTokenAndAccessTokenAsync = function (id_token, nonce, access_token) {
    log("OidcClient.validateIdTokenAndAccessTokenAsync");

    var client = this;

    return client.validateIdTokenAsync(id_token, nonce, access_token).then(function (id_token_contents) {

        return client.validateAccessTokenAsync(id_token_contents, access_token).then(function () {

            return id_token_contents;

        });

    });
}

OidcClient.prototype.processResponseAsync = function (queryString) {
    log("OidcClient.processResponseAsync");

    var client = this;
    var settings = client._settings;

    var request_state = settings.request_state_store.getItem(settings.request_state_key);
    settings.request_state_store.removeItem(settings.request_state_key);

    if (!request_state) {
        return error("No request state loaded");
    }

    request_state = JSON.parse(request_state);
    if (!request_state) {
        return error("No request state loaded");
    }

    if (!request_state.state) {
        return error("No state loaded");
    }

    var result = parseOidcResult(queryString);
    if (!result) {
        return error("No OIDC response");
    }

    if (result.error) {
        return error(result.error);
    }

    if (result.state !== request_state.state) {
        return error("Invalid state");
    }

    if (request_state.oidc) {
        if (!result.id_token) {
            return error("No identity token");
        }

        if (!request_state.nonce) {
            return error("No nonce loaded");
        }
    }

    if (request_state.oauth) {
        if (!result.access_token) {
            return error("No access token");
        }

        if (!result.token_type || result.token_type.toLowerCase() !== "bearer") {
            return error("Invalid token type");
        }

        if (!result.expires_in) {
            return error("No token expiration");
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
            session_state : result.session_state
        };
    });
}
'use strict';

var exports = module.exports = {
    environment: process.env.NODE_ENV || 'LOCAL',

    log: function(message) {
        if(this.environment === 'LOCAL')
            console.log(message);
    },

    copy: function(obj, target) {
        target = target || {};
        for (var key in obj) {
            if (obj.hasOwnProperty(key)) {
                target[key] = obj[key];
            }
        }
        return target;
    },

    rand: function() {
        return ((Date.now() + Math.random()) * Math.random()).toString().replace(".", "");
    },

    error: function(promiseFactory, message) {
        return promiseFactory.reject(Error(message));
    },

    parseOidcResult: function(queryString) {
        queryString = queryString || location.hash;

        var idx = queryString.lastIndexOf("#");
        if (idx >= 0) {
            queryString = queryString.substr(idx + 1);
        }

        var params = {},
            regex = /([^&=]+)=([^&]*)/g,
            m;

        var counter = 0;
        while (m = regex.exec(queryString)) {
            params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
            if (counter++ > 50) {
                return {
                    error: "Response exceeded expected number of parameters"
                };
            }
        }

        for (var prop in params) {
            return params;
        }
    },

    getJson: function() {
        var config = {};

        if (token) {
            config.headers = {"Authorization": "Bearer " + token};
        }

        return _httpRequest.getJSON(url, config);
    }
};
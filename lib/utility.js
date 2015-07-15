'use strict';
var rp = require("request-promise");
module.exports = {

    verbose_logging: false,

    log: function (message) {
        var self = this;

        if (self.verbose_logging) {
            console.log(message);
        }
    },

    copy: function (obj, target) {
        target = target || {};
        for (var key in obj) {
            if (obj.hasOwnProperty(key)) {
                target[key] = obj[key];
            }
        }
        return target;
    },

    rand: function () {
        return ((Date.now() + Math.random()) * Math.random()).toString().replace(".", "");
    },

    getJson: function (url, token, httpConfig) {

        var config = this.copy(httpConfig);

        if (token) {
            config.headers = { "Authorization": "Bearer " + token };
        }

        config.uri = url;
        config.json = true;

        return rp(config);
    }
};
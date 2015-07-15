'use strict';
var httpRequest = require('./httpRequest.js');

module.exports = {

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

    getJson: function(url, token, httpConfig) {
        
        var config = this.copy(httpConfig);

        if (token) {
            config.headers = {"Authorization": "Bearer " + token};
        }

        return httpRequest.getJSON(url, config);
    }
};
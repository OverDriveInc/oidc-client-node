# oidc-client

OpenID Connect (OIDC) client server side library

## Install
`$ npm install`

## Configuration Options

 ```javascript
var oidcConfig = {
  scope: 'profile roles',
  client_id: 'implicit_client',
  callbackURL: '/auth/oidc/callback', // callback url, can be absolute or relative
  authority: 'https://localhost:50000/core'; //'--insert-your-openid-provider-domain-name-here--',
  response_type: "id_token token", 
  response_mode: "form_post",
  scopeSeparator: ' ',
  verbose_logging: true,
  httpSettings: { strictSSL = true } // optional http settings for Request
};
```

## Local options

You can also set options on a per request basis and have those options merged in. For example:

```javascript
var localOptions = {
  callbackURL: '/auth/oidc/callback', 
  acr_values: "tenant:12"
};
    
var oidcClient = new OidcClient(req, res, oidcConfig);

oidcClient.mergeRequestOptions(req, localOptions);

**Note: You are currently required to merge request options (even if they are empty), otherwise the client may not work appropriately.**
```
 
## Implicit Flow Configuration Example
 
 ```javascript
var oidcConfig = {
  scope: 'profile roles',
  client_id: 'implicit_client',
  callbackURL: '/auth/oidc/callback',
  authority: 'https://localhost:50000/core';
  response_type: "id_token token", 
  response_mode: "form_post",
  scopeSeparator: ' ',
  verbose_logging: true
};
```

## Code Flow Configuration Example
 
 ```javascript
var oidcConfig = {
  scope: 'profile roles offline_access', // offline is not required for code flow, but is typically used in this flow to get refresh tokens
  client_id: 'implicit_client',
  callbackURL: '/auth/oidc/callback',
  authority: 'https://localhost:50000/core';
  response_type: "code", 
  response_mode: "form_post",
  scopeSeparator: ' ',
  verbose_logging: true
};
```

## Wiring up your routes

Wire up your routes (this example uses req.body which was based on express / body parser) 

```javascript
app.get('/auth/oidc/login',
  function (req, res) {
    
    var oidcClient = new OidcClient(req, res, oidcConfig);
        
    var tokenRequest = oidcClient.createTokenRequestAsync();
    
    tokenRequest.then(function (results) {
      console.log('about to redirect');
      res.redirect(results.url);  
    }).catch(function(error){
        console.log('error generating redirect url: ' + error);
    });
});

app.post(/auth/oidc/callback,
  function (req, res) {
    
    var oidcClient = new OidcClient(req, res, oidcConfig);
    
    var tokenResponse = oidcClient.processResponseAsync(req.body);
    
    tokenResponse.then(function (results) {
      console.log(results);
    }).catch(function(error) {
        console.log('error parsing token response: ' + error);
    });
    
    console.log('Made it to the end of the response function');
});
```

## Response Example

Here's an example of all the possible data in a response. What values you get back will dependent on the flow as well as the identity provider you are integrating with.

```javascript
{
  "profile": {
    "sub": "1",
    "name": "User"
  },
  "id_token": "613bfdfc867a4a838784965582aecfbb",
  "access_token": "b976452d0cb94ced8825f3297bed2628",
  "refresh_token": "62fd0a32fbc0496ab21e48835343b852",
  "expires_in": 360
}
```
# oidc-client

OpenID Connect (OIDC) client server side library

## Install
 npm install
 
 Set up default configurations
 
 ```javascript
 var OP_DOMAIN_NAME = 'https://localhost:50000/core'; //'--insert-your-openid-provider-domain-name-here--'

var CLIENT_ID = 'implicit_client'; 
var CALLBACK_URL = '/auth/oidc/callback';

var oidcConfig = {
  scope: 'profile roles',
  client_id: CLIENT_ID,
 // clientSecret: CLIENT_SECRET,
  callbackURL: CALLBACK_URL,
  authority: OP_DOMAIN_NAME,
  response_type: "id_token token", 
  response_mode: "form_post",
  scopeSeparator: ' ',
  verbose_logging: true
};
```

Wire up your routes (this example uses req.body which was based on express / body parser) 

```javascript
app.get('/auth/oidc/login',
  function(req, res){
    var localOptions = {callbackURL: CALLBACK_URL, acr_values: "tenant:12" };
    
    var oidcClient = new OidcClient(req, res, oidcConfig);
    
    oidcClient.mergeRequestOptions(req, localOptions);
    
    var tokenRequest = oidcClient.createTokenRequestAsync();
    
    tokenRequest.then(function (results) {
      console.log('about to redirect');
      res.redirect(results.url);  
    }).catch(function(error){
        console.log('error generating redirect url: ' + error);
    });
});

app.post(CALLBACK_URL,
  function(req, res) {
    
    var oidcClient = new OidcClient(req, res, oidcConfig);
       
    var tokenResponse = oidcClient.processResponseAsync(req.body);
    
    tokenResponse.then(function (results) {
      console.log(results);
    
    }).catch(function(error){
        console.log('error parsing token response: ' + error);
    });;
    
    console.log('Made it to the end of the response function');
   
});
```
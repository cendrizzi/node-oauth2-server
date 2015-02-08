# Node OAuth2 Server [![Build Status](https://travis-ci.org/thomseddon/node-oauth2-server.png?branch=2.0)](https://travis-ci.org/thomseddon/node-oauth2-server)

Complete, compliant and well tested module for implementing an OAuth2 Server/Provider with [express](http://expressjs.com/) in [node.js](http://nodejs.org/)

## Installation

```
npm install oauth2-server
```

## Quick Start

The module provides two middlewares, one for authorization and routing, another for error handling, use them as you would any other middleware:

```js
var express = require('express'),
    bodyParser = require('body-parser'),
    oauthserver = require('oauth2-server');

var app = express();

app.use(bodyParser.urlencoded({ extended: true }));

app.use(bodyParser.json());

app.oauth = oauthserver({
  model: {}, // See below for specification
  grants: ['password'],
  debug: true
});

app.all('/oauth/token', app.oauth.grant());

app.get('/', app.oauth.authorise(), function (req, res) {
  res.send('Secret area');
});

app.use(app.oauth.errorHandler());

app.listen(3000);
```

After running with node, visting http://127.0.0.1:3000 should present you with a json response saying your access token could not be found.

Note: As no model was actually implemented here, delving any deeper, i.e. passing an access token, will just cause a server error. See below for the specification of what's required from the model.

## Features

- Supports authorization_code, password, refresh_token, client_credentials and extension (custom) grant types
- Implicitly supports any form of storage e.g. PostgreSQL, MySQL, Mongo, Redis...
- Full test suite

## Options

- *string* **model**
 - Model object (see below)
- *array* **grants**
 - grant types you wish to support, currently the module supports `password` and `refresh_token`
  - Default: `[]`
- *function|boolean* **debug**
 - If `true` errors will be  logged to console. You may also pass a custom function, in which case that function will be called with the error as its first argument
  - Default: `false`
- *number* **accessTokenLifetime**
 - Life of access tokens in seconds
 - If `null`, tokens will considered to never expire
  - Default: `3600`
- *number* **refreshTokenLifetime**
 - Life of refresh tokens in seconds
 - If `null`, tokens will considered to never expire
  - Default: `1209600`
- *number* **authCodeLifetime**
 - Life of auth codes in seconds
  - Default: `30`
- *regexp* **clientIdRegex**
 - Regex to sanity check client id against before checking model. Note: the default just matches common `client_id` structures, change as needed 
  - Default: `/^[a-z0-9-_]{3,40}$/i`
- *boolean* **passthroughErrors**
 - If true, **non grant** errors will not be handled internally (so you can ensure a consistent format with the rest of your api)
- *boolean* **continueAfterResponse**
 - If true, `next` will be called even if a response has been sent (you probably don't want this)

## Model Specification

The module requires a model object through which some aspects or storage, retrieval and custom validation are abstracted.
The last parameter of all methods is a callback of which the first parameter is always used to indicate an error.

Note: see https://github.com/thomseddon/node-oauth2-server/tree/master/examples/postgresql for a full model example using postgres.

### Always Required

#### getAccessToken (bearerToken, callback)
- *string* **bearerToken**
 - The bearer token (access token) that has been provided
- *function* **callback (error, accessToken)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *object* **accessToken**
     - The access token retrieved form storage or falsey to indicate invalid access token
     - Must contain the following keys:
         - *date* **expires**
             - The date when it expires
             - `null` to indicate the token **never expires**
         - *mixed* **user** *or* *string|number* **userId**
             - If a `user` key exists, this is saved as `req.user`
             - Otherwise a `userId` key must exist, which is saved in `req.user.id`

#### getClient (clientId, clientSecret, callback)
- *string* **clientId**
- *string|null* **clientSecret**
 - If null, omit from search query (only search by clientId)
- *function* **callback (error, client)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *object* **client**
     - The client retrieved from storage or falsey to indicate an invalid client
     - Saved in `req.client`
     - Must contain the following keys:
         - *string* **clientId**
         - *string* **redirectUri** (`authorization_code` grant type only)

#### grantTypeAllowed (clientId, grantType, callback)
- *string* **clientId**
- *string* **grantType**
- *function* **callback (error, allowed)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *boolean* **allowed**
     - Indicates whether the grantType is allowed for this clientId

#### saveAccessToken (accessToken, clientId, expires, user, callback)
- *string* **accessToken**
- *string* **clientId**
- *date* **expires**
- *object* **user**
- *function* **callback (error)**
 - *mixed* **error**
     - Truthy to indicate an error


### Required for `authorization_code` grant type

#### getAuthCode (authCode, callback)
- *string* **authCode**
- *function* **callback (error, authCode)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *object* **authCode**
     - The authorization code retrieved form storage or falsey to indicate invalid code
     - Must contain the following keys:
         - *string|number* **clientId**
             - client id associated with this auth code
         - *date* **expires**
             - The date when it expires
         - *string|number* **userId**
             - The userId

#### saveAuthCode (authCode, clientId, expires, user, callback)
- *string* **authCode**
- *string* **clientId**
- *date* **expires**
- *mixed* **user**
   - Whatever was passed as `user` to the codeGrant function (see example)
- *function* **callback (error)**
 - *mixed* **error**
     - Truthy to indicate an error


### Required for `password` grant type

#### getUser (username, password, callback)
- *string* **username**
- *string* **password**
- *function* **callback (error, user)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *object* **user**
     - The user retrieved from storage or falsey to indicate an invalid user
     - Saved in `req.user`
     - Must contain the following keys:
         - *string|number* **id**

### Required for `refresh_token` grant type

#### saveRefreshToken (refreshToken, clientId, expires, user, callback)
- *string* **refreshToken**
- *string* **clientId**
- *date* **expires**
- *object* **user**
- *function* **callback (error)**
 - *mixed* **error**
     - Truthy to indicate an error

#### getRefreshToken (refreshToken, callback)
- *string* **refreshToken**
 - The bearer token (refresh token) that has been provided
- *function* **callback (error, refreshToken)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *object* **refreshToken**
     - The refresh token retrieved form storage or falsey to indicate invalid refresh token
     - Must contain the following keys:
         - *string|number* **clientId**
             - client id associated with this token
         - *date* **expires**
             - The date when it expires
             - `null` to indicate the token **never expires**
         - *string|number* **userId**
             - The userId


### Optional for Refresh Token grant type

#### revokeRefreshToken (refreshToken, callback)
The spec does not actually require that you revoke the old token - hence this is optional (Last paragraph: http://tools.ietf.org/html/rfc6749#section-6)
- *string* **refreshToken**
- *function* **callback (error)**
 - *mixed* **error**
     - Truthy to indicate an error

### Required for [extension grant](#extension-grants) grant type

#### extendedGrant (grantType, req, callback)
- *string* **grantType**
 - The (custom) grant type
- *object* **req**
 - The raw request
- *function* **callback (error, supported, user)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *boolean* **supported**
     - Whether you support the grant type
 - *object* **user**
     - The user retrieved from storage or falsey to indicate an invalid user
     - Saved in `req.user`
     - Must contain the following keys:
         - *string|number* **id**

### Required for `client_credentials` grant type

#### getUserFromClient (clientId, clientSecret, callback)
- *string* **clientId**
- *string* **clientSecret**
- *function* **callback (error, user)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *object* **user**
     - The user retrieved from storage or falsey to indicate an invalid user
     - Saved in `req.user`
     - Must contain the following keys:
         - *string|number* **id**


### Optional

#### generateToken (type, req, callback)
- *string* **type**
 - `accessToken` or `refreshToken`
- *object* **req**
 - The current express request
- *function* **callback (error, token)**
 - *mixed* **error**
     - Truthy to indicate an error
 - *string|object|null* **token**
     - *string* indicates success
     - *null* indicates to revert to the default token generator
     - *object* indicates a reissue (i.e. will not be passed to saveAccessToken/saveRefreshToken)
         - Must contain the following keys (if object):
           - *string* **accessToken** OR **refreshToken** dependant on type

## Extension Grants
You can support extension/custom grants by implementing the extendedGrant method as outlined above.
Any grant type that is a valid URI will be passed to it for you to handle (as [defined in the spec](http://tools.ietf.org/html/rfc6749#section-4.5)).
You can access the grant type via the first argument and you should pass back supported as `false` if you do not support it to ensure a consistent (and compliant) response.

## Example using the `password` grant type

First you must insert client id/secret and user into storage. This is out of the scope of this example.

To obtain a token you should POST to `/oauth/token`. You should include your client credentials in
the Authorization header ("Basic " + client_id:client_secret base64'd), and then grant_type ("password"),
username and password in the request body, for example:

```
POST /oauth/token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=johndoe&password=A3ddj3w
```
This will then call the following on your model (in this order):
 - getClient (clientId, clientSecret, callback)
 - grantTypeAllowed (clientId, grantType, callback)
 - getUser (username, password, callback)
 - saveAccessToken (accessToken, clientId, expires, user, callback)
 - saveRefreshToken (refreshToken, clientId, expires, user, callback) **(if using)**

Provided there weren't any errors, this will return the following (excluding the `refresh_token` if you've not enabled the refresh_token grant type):

```
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"bearer",
  "expires_in":3600,
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
}
```

## Example using the `authorization_code` grant type

Authorization code grant type is common to implement. It's advantage is that the client application never has access or 
needs to save your users username and password. Instead any application will login on your site and be redirected back
to the app after the user has explicitly granted access.

### Setup

To support this grant type you must ensure that your models implement the necessary model methods as documented above.
Of special importance is that the `getClient` method returns the "redirectUri" value.

First, setup the authorize route. If logged in then it will show the authorize page. This page will typically give 
the user the option to grant or deny access the requesting app. If not logged in the user will be sent to the login page.

```
app.get('/oauth/authorize', function (req, res) {
    if (!req.session.user) {
        // If they aren't logged in, send them to your own login implementation
        return res.redirect('/oauth/login?redirect=' + req.path + '&client_id=' +
        req.query.client_id + '&redirect_uri=' + req.query.redirect_uri);
    }

    oauthModel.getClientById(req.query.client_id, function(err, clientRecord){
        res.render('oauth/authorize', {
            clientId: req.query.client_id,
            redirectUri: req.query.redirect_uri,
            appName: clientRecord.client_name       // Name of the app
        });
    });
});
```

Next, setup the login route, as mentioned this route will be redirected from GET/authorize if the user is not authenticated. In this
case it is assumed that the login route is being used both for rendering the form and handling it's submission. You'll 
notice after a successful login the user will be sent back to GET/authorize.

```
app.get('/oauth/login', function (req, res) {
    
    res.render('oauth/login', {
        clientId: req.query.client_id,
        redirectUri: req.query.redirect_uri
    });
});
```

Next, create the POST/authorize route. This route handles the path from GET/authorize when the user is authenticated.
This route should be passed the client_id and redirect_uri (either through POSTS or GET). In addition, through POST,
it should be passed the the variable of ALLOW, which should be true or false (using this example).

```
// Handle authorize
app.post('/oauth/authorize', function (req, res, next) {
    if (!req.session.user) {
        return res.redirect('/oauth/login?client_id=' + req.query.client_id +
        '&redirect_uri=' + req.query.redirect_uri);
    }

    next();
}, app.oauth.authCodeGrant(function (req, next) {
    // The first param should to indicate an error
    // The second param should a bool to indicate if the user did authorize the app
    // The third param should for the user/uid (only used for passing to saveAuthCode)
    next(null, req.body.allow, req.session.user.id);
}));
```

If successful the a new auth code record will be created and the grant code will be sent to the redirect_uri value. After
the consuming application has the grant code they will use it (before the auth code record expires) to get a token. The
token handler should be like this:

```
app.all('/oauth/token', app.oauth.grant());
```

The middleware provides all the capability needed to handle getting a token.

### Usage

The following shows quickly how the process of using the new routes works.

First, a call will be made to the GET/authorize endpoint with the following request:

```
GET /oauth/authorize?client_id=26eeeb16-1b33-40e0-aaac-53d14e742a94&scope=&state=121959&redirect_uri=https://www.mycallback.com/oauth2/callback&response_type=code HTTP/1.1
Host: server.example.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8
```

As this is the first time the user the oauth 2 server will redirect the call to the login page. Once the user provides
the correct credentials the user should be sent back to authorize. As the user is now logged in they will be presented
with an authorization screen of your making. It should ask the user if they want to grant access or not. Assuming the 
user grants access the request will look something similar to this:

```
POST /oauth/authorize?client_id=26eeeb16-1b33-40e0-aaac-53d14e742a94&redirect_uri=https://www.mycallback.com/oauth2/callback&response_type=code HTTP/1.1
Host: server.example.com
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8
Cookie: session.cookie

allow=true&response_type=code
```
Assuming all is okay with the request a new auth code record is created and the consuming application will be redirected 
to the redirect_uri with the cod attached

```
https://www.mycallback.com/oauth2/callback&response_type=code&code=ca313597a932cebed857f588942b8ff896c4ddb8
```

Now the consuming application should request a token to get access to your api like the following:
 
```
POST /oauth/token HTTP/1.1
Host: server.example.com
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8

code=42a0465166dd6252a4e7f3f345ddb5d4d6905b193&grant_type=authorization_code&client_id=26eeeb16-1c33-42e2-aaac-53d14e742a94&client_secret=40f54704-dbd8-4779-abac-0830f747d48c
```

And should get a response like the following, with the token (with the options refresh token):

 ```
 HTTP/1.1 200 OK
 X-Powered-By: Express

 
 {"token_type":"bearer","access_token":"e88aefddd2ca8c7517f30f0bbcabasdfd2ae5e51e","expires_in":86400,"refresh_token":"7c116f36e3e75b479b51c3f550e9b1d7fd6955b0"}
 ```

## Changelog

See: https://github.com/thomseddon/node-oauth2-server/blob/master/Changelog.md

## Credits

Copyright (c) 2013 Thom Seddon

## License

[Apache, Version 2.0](https://github.com/thomseddon/node-oauth2-server/blob/master/LICENSE)

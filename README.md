# Etalio PHP SDK (v.1.0.0)
CI-Master: &nbsp;[![Build Status](https://magnum.travis-ci.com/Etalio/etalio-php-sdk.png?token=7mZw6eGcbeDyg5gfzRsZ&branch=master)](https://magnum.travis-ci.com/Etalio/etalio-php-sdk)

CI-Develop: &nbsp;[![Build Status](https://magnum.travis-ci.com/Etalio/etalio-php-sdk.png?token=7mZw6eGcbeDyg5gfzRsZ&branch=develop)](https://magnum.travis-ci.com/Etalio/etalio-php-sdk)

Based on the [Facebook PHP SDK](https://github.com/facebook/facebook-php-sdk)

# Getting started

This assumes that there is an Etalio application created on the [developer portal](https://developer.etalio.com)

See the getting started guide for PHP to get started.

## Application key

Make sure you have the following from the key registration:

- Client id
- Client secret
- Redirect uri

The key will look something like this:

```clean
Application   : Test Application
KeyName       : My first key
ClientId      : d0d7ef3c-0807-4b0b-8354-22537dc21c40
Client secret : 6b527f6b-2df0-4104-a322-1704b690cd75
Scopes        :
                scope.r
                scope.w
Redirects     :
                http://example.com/auth/etalio/callback
                http://localhost/auth/etalio/callback
```

----

## Configure

Add this snippet to your project and replace the values from the key:

```php
require_once('etalio_with_session_store.php');

$etalio = new \Etalio\EtalioWithSessionStore([
  'appId'  => "<your client_id>",
  'secret' => "<your client secret>",
  'redirect_uri' => "<the redirect back to your site>",
  'debug' => false // Optional but useful when debugging the calls back to the etalio api
]);
```

----

## Authenticating

When you want to authenticate the user, redirect them to the Etalio login and signup URL that you get from accessing:

```php
$etalio->getLoginUrl([
  'scope' => 'scope.r scope.w', // The scopes for your application
  'acr_values' => '2', // 2 => Single factor authentication, 3 => 2 factor authentication
  'prompt' => '', // login => user needs to re-authenticate, consent => user needs to accept your scopes again, none => the user will not be presented with a UI. If authentication fails an error message will be produced., '' => default behaviour
])
```

This will redirect the user to the Etalio OAuth2 consent pages. After the user either approved or rejected your
application, it will get redirected back to the redirect URI you defined when creating the key.
Run the ```authenticateUser()``` function in the redirect request.

```php
$etalio->authenticateUser();
```

This method will look for the authentication headers in the ```$_request``` object and take care of the callbacks to
Etalio in order to exchange the OAuth2 code header from the redirect and your client secret to an authentication
token and a refreshtoken.

On the next request you can check if the user is authenticated, by calling:

```php
$etalio->isAuthenticated();
```

## API

If you want to know more about the user, for instance their name, make a call to

```php
$etalio->getUserinfo();
```

The response will be similar to this.

```javascript
{
  "id": "dde9536c-2ca2-4fdc-a710-17ef0a58ede8",
  "msisdn": {
    "country_code": 386,
    "number": "+38640123456"
  },
  "email": {
    "address": "email@example.com",
    "authenticated": true
  },
  "name": "Profile Name",
  "verified": true,
  "links": [{
    "rel": "my-apps",
    "href": "https://api.etalio.com/v1/profile/me/applications"
  }]
}
```


## License

Copyright 2014 Ericsson AB

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
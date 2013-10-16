<?php
/**
 * Copyright 2011 Etalio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

require '../src/etalio.php';

// Create our Application instance (replace this with your appId and secret).
$etalio = new Etalio(array(
  'appId'  => '344617158898614',
  'secret' => '6dc8ac871858b34798bc2488200e503d',
));

// Get User ID
$user = $etalio->getUser();

// We may or may not have this data based on whether the user is logged in.
//
// If we have a $user id here, it means we know the user is logged into
// Etalio, but we don't know if the access token is valid. An access
// token is invalid if the user logged out of Etalio.

if ($user) {
  try {
    // Proceed knowing you have a logged in user who's authenticated.
    $user_profile = $etalio->api('/me');
  } catch (EtalioApiException $e) {
    error_log($e);
    $user = null;
  }
}

// Login or logout url will be needed depending on current user state.
if ($user) {
  $logoutUrl = $etalio->getLogoutUrl();
} else {
  $statusUrl = $etalio->getLoginStatusUrl();
  $loginUrl = $etalio->getLoginUrl();
}

// This call will always work since we are fetching public data.
$naitik = $etalio->api('/naitik');

?>
<!doctype html>
<html>
  <head>
    <title>php-sdk</title>
    <style>
      body {
        font-family: 'Lucida Grande', Verdana, Arial, sans-serif;
      }
      h1 a {
        text-decoration: none;
        color: #3b5998;
      }
      h1 a:hover {
        text-decoration: underline;
      }
    </style>
  </head>
  <body>
    <h1>php-sdk</h1>

    <?php if ($user): ?>
      <a href="<?php echo $logoutUrl; ?>">Logout</a>
    <?php else: ?>
      <div>
        Check the login status using OAuth 2.0 handled by the PHP SDK:
        <a href="<?php echo $statusUrl; ?>">Check the login status</a>
      </div>
      <div>
        Login using OAuth 2.0 handled by the PHP SDK:
        <a href="<?php echo $loginUrl; ?>">Login with Etalio</a>
      </div>
    <?php endif ?>

    <h3>PHP Session</h3>
    <pre><?php print_r($_SESSION); ?></pre>

    <?php if ($user): ?>

      <h3>Your User Object (/me)</h3>
      <pre><?php print_r($user_profile); ?></pre>
    <?php else: ?>
      <strong><em>You are not Connected.</em></strong>
    <?php endif ?>
  </body>
</html>

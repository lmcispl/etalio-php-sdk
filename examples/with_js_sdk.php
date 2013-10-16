<?php

require '../src/etalio.php';

$etalio = new Etalio(array(
  'appId'  => '344617158898614',
  'secret' => '6dc8ac871858b34798bc2488200e503d',
));

// See if there is a user from a cookie
$user = $etalio->getUser();

if ($user) {
  try {
    // Proceed knowing you have a logged in user who's authenticated.
    $user_profile = $etalio->api('/me');
  } catch (EtalioApiException $e) {
    echo '<pre>'.htmlspecialchars(print_r($e, true)).'</pre>';
    $user = null;
  }
}

?>
<!DOCTYPE html>
<html xmlns:fb="http://www.etalio.com/2008/fbml">
  <body>
    <?php if ($user) { ?>
      Your user profile is
      <pre>
        <?php print htmlspecialchars(print_r($user_profile, true)) ?>
      </pre>
    <?php } else { ?>
      <fb:login-button></fb:login-button>
    <?php } ?>
    <div id="fb-root"></div>
    <script>
      window.fbAsyncInit = function() {
        FB.init({
          appId: '<?php echo $etalio->getAppID() ?>',
          cookie: true,
          xfbml: true,
          oauth: true
        });
        FB.Event.subscribe('auth.login', function(response) {
          window.location.reload();
        });
        FB.Event.subscribe('auth.logout', function(response) {
          window.location.reload();
        });
      };
      (function() {
        var e = document.createElement('script'); e.async = true;
        e.src = document.location.protocol +
          '//connect.etalio.net/en_US/all.js';
        document.getElementById('fb-root').appendChild(e);
      }());
    </script>
  </body>
</html>

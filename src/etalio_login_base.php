<?php
require_once('etalio_api_exception.php');

if (!function_exists('curl_init')) {
  throw new Exception('Etalio needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
  throw new Exception('Etalio needs the JSON PHP extension.');
}


/**
 * Provides access to the Etalio Platform.  This class provides
 * a majority of the functionality needed for handshaking, but the class is abstract
 * because it is designed to be sub-classed.  The subclass must
 * implement the four abstract methods listed at the bottom of
 * the file.
 */
abstract class EtalioLoginBase
{
  /**
   * Server Url
   */
  const BASE_URL = "https://api-etalio.3fs.si";

  /**
   * APi version
   */
  const API_VERSION = "v0.0.1";

  /**
   * Version of this SDK
   */
  const VERSION = '0.1.0';

  /**
   * List of query parameters that get automatically dropped when rebuilding
   * the current URL.
   */
  protected static $DROP_QUERY_PARAMS = array(
    'code',
    'state',
  );

  /**
   * Default options for curl.
   */
  protected $curlOpts;

  /**
   * Maps aliases to Etalio domains.
   */
  protected $domainMap;
  /**
   * The Application ID.
   *
   * @var string
   */
  protected $appId;

  /**
   * The Application App Secret.
   *
   * @var string
   */
  protected $appSecret;

  /**
   * The ID of the Etalio user, or 0 if the user is logged out.
   *
   * @var integer
   */
  protected $user;

  /**
   * A CSRF state variable to assist in the defense against CSRF attacks.
   */
  protected $state;

  /**
   * The OAuth access token received in exchange for a valid authorization
   * code.  null means the access token has yet to be determined.
   *
   * @var string
   */
  protected $accessToken = null;

  /**
   * Initialize a Etalio Application.
   *
   * The configuration:
   * - appId: the application ID
   * - secret: the application secret
   *
   * @param array $config The application configuration
   */
  public function __construct($config) {
    //Populate with bare minimum of Etalio functionality, add more in sub classes
    $this->domainMap = array(
      'api'       => self::BASE_URL,
      'www'       => 'http://www.etalio.com',
      'oauth2'    => self::BASE_URL . '/oauth2',
      'token'     => self::BASE_URL . '/oauth2/token',
      'profile'   => self::BASE_URL . '/' . self::API_VERSION . '/user',
    );
    $this->curlOpts = array(
      CURLOPT_CONNECTTIMEOUT => 10,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => 60,
      CURLOPT_USERAGENT      => 'etalio-php-'.self::VERSION,
    );
    if(!isset($config['appId']) || !isset($config['secret'])) {
      throw new Exception("Both Application ID and Application secret are mandatory configuration parameters", 1);
    }
    $this->setAppId($config['appId']);
    $this->setAppSecret($config['secret']);
    $state = $this->getPersistentData('state');
    if (!empty($state)) {
      $this->state = $state;
    }
  }

  /**
   * Set the Application ID.
   *
   * @param string $appId The Application ID
   * @return BaseEtalio
   */
  public function setAppId($appId) {
    $this->appId = $appId;
    return $this;
  }

  /**
   * Get the Application ID.
   *
   * @return string the Application ID
   */
  public function getAppId() {
    return $this->appId;
  }

  /**
   * Get the flags for CURL
   */
  public function getCurlOpts() {
    return $this->curlOpts;
  }

  /**
   * Set the App Secret.
   *
   * @param string $appSecret The App Secret
   * @return BaseEtalio
   */
  public function setAppSecret($appSecret) {
    $this->appSecret = $appSecret;
    return $this;
  }

  /**
   * Get the App Secret.
   *
   * @return string the App Secret
   */
  public function getAppSecret() {
    return $this->appSecret;
  }

  /**
   * Sets the access token for api calls.  Use this if you get
   * your access token by other means and just want the SDK
   * to use it.
   *
   * @param string $access_token an access token.
   * @return BaseEtalio
   */
  public function setAccessToken($access_token) {
    $this->accessToken = $access_token;
    return $this;
  }

  /**
   * Extend an access token, while removing the short-lived token that might
   * have been generated via client-side flow. Thanks to http://bit.ly/b0Pt0H
   * for the workaround.
   *
   * The method is probably not applicable for Etalio /Mkson
   */
  // public function setExtendedAccessToken() {
  //   try {
  //     // need to circumvent json_decode by calling _oauthRequest
  //     // directly, since response isn't JSON format.
  //     $access_token_response = $this->_oauthRequest(
  //       $this->getUrl('graph', '/oauth/access_token'),
  //       $params = array(
  //         'client_id' => $this->getAppId(),
  //         'client_secret' => $this->getAppSecret(),
  //         'grant_type' => 'authorization_code',
  //       )
  //     );
  //   }
  //   catch (EtalioApiException $e) {
  //     // most likely that user very recently revoked authorization.
  //     // In any event, we don't have an access token, so say so.
  //     return false;
  //   }

  //   if (empty($access_token_response)) {
  //     return false;
  //   }

  //   $response_params = array();
  //   parse_str($access_token_response, $response_params);

  //   if (!isset($response_params['access_token'])) {
  //     return false;
  //   }

  //   $this->destroySession();

  //   $this->setPersistentData(
  //     'access_token', $response_params['access_token']
  //   );
  // }

  /**
   * Determines the access token that should be used for API calls.
   * The first time this is called, $this->accessToken is set equal
   * to either a valid user access token, or it's set to the application
   * access token if a valid user access token wasn't available.  Subsequent
   * calls return whatever the first call returned.
   *
   * @return string The access token
   */
  public function getAccessToken() {
    if ($this->accessToken !== null) {
      // we've done this already and cached it.  Just return.
      return $this->accessToken;
    }

    // first establish access token to be the application
    // access token, in case we navigate to the /oauth/access_token
    // endpoint, where SOME access token is required.
    $this->setAccessToken($this->getApplicationAccessToken());
    $user_access_token = $this->getUserAccessToken();
    if ($user_access_token) {
      $this->setAccessToken($user_access_token);
    }

    return $this->accessToken;
  }

  /**
   * Determines and returns the user access token, first using
   * the signed request if present, and then falling back on
   * the authorization code if present.  The intent is to
   * return a valid user access token, or false if one is determined
   * to not be available.
   *
   * @return string A valid user access token, or false if one
   *                could not be determined.
   */
  protected function getUserAccessToken() {
    $code = $this->getCode();
    if ($code && $code != $this->getPersistentData('code')) {
      $access_token = $this->getAccessTokenFromCode($code);
      if ($access_token) {
        $this->setPersistentData('code', $code);
        $this->setPersistentData('access_token', $access_token);
        return $access_token;
      }

      // code was bogus, so everything based on it should be invalidated.
      $this->clearAllPersistentData();
      return false;
    }

    // as a fallback, just return whatever is in the persistent
    // store, knowing nothing explicit (signed request, authorization
    // code, etc.) was present to shadow it (or we saw a code in $_REQUEST,
    // but it's the same as what's in the persistent store)
    return $this->getPersistentData('access_token');
  }

  /**
   * Get the UID of the connected user, or 0
   * if the Etalio user is not connected.
   *
   * @return string the UID if available.
   */
  public function getUser() {
    if ($this->user !== null) {
      // we've already determined this and cached the value.
      return $this->user;
    }

    return $this->user = $this->getUserFromAvailableData();
  }

  /**
   * Determines the connected user by first examining any signed
   * requests, then considering an authorization code, and then
   * falling back to any persistent store storing the user.
   *
   * @return integer The id of the connected Etalio user,
   *                 or 0 if no such user exists.
   */
  protected function getUserFromAvailableData() {

    $user = $this->getPersistentData('user_id', $default = 0);
    $persisted_access_token = $this->getPersistentData('access_token');

    // use access_token to fetch user id if we have a user access_token, or if
    // the cached access token has changed.
    $access_token = $this->getAccessToken();
    if ($access_token &&
        $access_token != $this->getApplicationAccessToken() &&
        !($user && $persisted_access_token == $access_token)) {
      $user = $this->getUserFromAccessToken();
      if ($user) {
        $this->setPersistentData('user_id', $user);
      } else {
        $this->clearAllPersistentData();
      }
    }

    return $user;
  }

  /**
   * Get a Login URL for use with redirects. By default, full page redirect is
   * assumed. If you are using the generated URL with a window.open() call in
   * JavaScript, you can pass in display=popup as part of the $params.
   *
   * The parameters:
   * - redirect_uri: the url to go to after a successful login
   * - scope: comma separated list of requested extended perms
   *
   * @param array $params Provide custom parameters
   * @return string The URL for the login flow
   */
  public function getLoginUrl($params=array()) {
    $this->establishCSRFTokenState();
    $currentUrl = $this->getCurrentUrl();

    // if 'scope' is passed as an array, convert to comma separated list
    $scopeParams = isset($params['scope']) ? $params['scope'] : null;
    if ($scopeParams && is_array($scopeParams)) {
      $params['scope'] = implode(',', $scopeParams);
    }

    return $this->getUrl(
      'oauth2',
      array_merge(
        array(
          'client_id'     => $this->getAppId(),
          'redirect_uri'  => $currentUrl, // possibly overwritten
          'state'         => $this->state,
          'sdk'           => 'php-sdk-'.self::VERSION,
          'response_type' => 'code'
        ),
        $params
      ));
  }

  /**
   * Make an API call.
   *
   * @return mixed The decoded response
   */
  public function api(/* polymorphic */) {
    $args = func_get_args();
    if (is_array($args[0])) {
      return $this->_restserver($args[0]);
    } else {
      return call_user_func_array(array($this, 'profile'), $args);
    }
  }

  /**
   * Constructs and returns the name of the coookie that potentially contain
   * metadata. The cookie is not set by the BaseEtalio class, but it may be
   * set by the JavaScript SDK.
   *
   * @return string the name of the cookie that would house metadata.
   */
  protected function getMetadataCookieName() {
    return 'fbm_'.$this->getAppId();
  }

  /**
   * Get the authorization code from the query parameters, if it exists,
   * and otherwise return false to signal no authorization code was
   * discoverable.
   *
   * @return mixed The authorization code, or false if the authorization
   *               code could not be determined.
   */
  protected function getCode() {
    if (isset($_REQUEST['code'])) {
      if ($this->state !== null &&
          isset($_REQUEST['state']) &&
          $this->state === $_REQUEST['state']) {

        // CSRF state has done its job, so clear it
        $this->state = null;
        $this->clearPersistentData('state');
        return $_REQUEST['code'];
      } else {
        self::errorLog('CSRF state token does not match one provided.');
        return false;
      }
    }

    return false;
  }

  /**
   * Retrieves the UID with the understanding that
   * $this->accessToken has already been set and is
   * seemingly legitimate.  It relies on Etalio's Graph API
   * to retrieve user information and then extract
   * the user ID.
   *
   * @return integer Returns the UID of the Etalio user, or 0
   *                 if the Etalio user could not be determined.
   */
  protected function getUserFromAccessToken() {
    try {
      $user_info = $this->api('/me');
      return $user_info['id'];
    } catch (EtalioApiException $e) {
      return 0;
    }
  }

  /**
   * Returns the access token that should be used for logged out
   * users when no authorization code is available.
   *
   * @return string The application access token, useful for gathering
   *                public information about users and applications.
   */
  public function getApplicationAccessToken() {
    return $this->appId.'|'.$this->appSecret;
  }

  /**
   * Lays down a CSRF state token for this process.
   *
   * @return void
   */
  protected function establishCSRFTokenState() {
    if ($this->state === null) {
      $this->state = md5(uniqid(mt_rand(), true));
      $this->setPersistentData('state', $this->state);
    }
  }

  /**
   * Retrieves an access token for the given authorization code
   * (previously generated from www.etalio.com on behalf of
   * a specific user).  The authorization code is sent to graph.etalio.com
   * and a legitimate access token is generated provided the access token
   * and the user for which it was generated all match, and the user is
   * either logged in to Etalio or has granted an offline access permission.
   *
   * @param string $code An authorization code.
   * @return mixed An access token exchanged for the authorization code, or
   *               false if an access token could not be generated.
   */
  protected function getAccessTokenFromCode($code, $redirect_uri = null) {
    if (empty($code)) {
      return false;
    }

    if ($redirect_uri === null) {
      $redirect_uri = $this->getCurrentUrl();
    }

    try {
      // need to circumvent json_decode by calling _oauthRequest
      // directly, since response isn't JSON format.
      $access_token_response =
        $this->_oauthRequest(
          $this->getUrl('graph', '/oauth/access_token'),
          $params = array('client_id' => $this->getAppId(),
                          'client_secret' => $this->getAppSecret(),
                          'redirect_uri' => $redirect_uri,
                          'code' => $code));
    } catch (EtalioApiException $e) {
      // most likely that user very recently revoked authorization.
      // In any event, we don't have an access token, so say so.
      return false;
    }

    if (empty($access_token_response)) {
      return false;
    }

    $response_params = array();
    parse_str($access_token_response, $response_params);
    if (!isset($response_params['access_token'])) {
      return false;
    }

    return $response_params['access_token'];
  }

  /**
   * Invoke the old restserver.php endpoint.
   *
   * @param array $params Method call object
   *
   * @return mixed The decoded response object
   * @throws EtalioApiException
   */
  protected function _restserver($params) {
    // generic application level parameters
    $params['api_key'] = $this->getAppId();
    $params['format'] = 'json-strings';

    $result = json_decode($this->_oauthRequest(
      $this->getApiUrl($params['method']),
      $params
    ), true);

    // results are returned, errors are thrown
    if (is_array($result) && isset($result['error_code'])) {
      $this->throwAPIException($result);
      // @codeCoverageIgnoreStart
    }
    // @codeCoverageIgnoreEnd

    $method = strtolower($params['method']);
    if ($method === 'auth.expiresession' ||
        $method === 'auth.revokeauthorization') {
      $this->destroySession();
    }

    return $result;
  }

  /**
   * Make a OAuth Request.
   *
   * @param string $url The path (required)
   * @param array $params The query/post data
   *
   * @return string The decoded response object
   * @throws EtalioApiException
   */
  protected function _oauthRequest($url, $params) {
    if (!isset($params['access_token'])) {
      $params['access_token'] = $this->getAccessToken();
    }

    if (isset($params['access_token'])) {
      $params['appsecret_proof'] = $this->getAppSecretProof($params['access_token']);
    }

    // json_encode all params values that are not strings
    foreach ($params as $key => $value) {
      if (!is_string($value)) {
        $params[$key] = json_encode($value);
      }
    }

    return $this->makeRequest($url, $params);
  }

  /**
   * Generate a proof of App Secret
   * This is required for all API calls originating from a server
   * It is a sha256 hash of the access_token made using the app secret
   *
   * @param string $access_token The access_token to be hashed (required)
   *
   * @return string The sha256 hash of the access_token
   */
  protected function getAppSecretProof($access_token) {
    return hash_hmac('sha256', $access_token, $this->getAppSecret());
  }

  /**
   * Makes an HTTP request. This method can be overridden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param string $url The URL to make the request to
   * @param array $params The parameters to use for the POST body
   * @param CurlHandler $ch Initialized curl handle
   *
   * @return string The response text
   */
  protected function makeRequest($url, $params, $ch=null) {
    if (!$ch) {
      $ch = curl_init();
    }

    $opts = self::$curlOpts;
    if ($this->getFileUploadSupport()) {
      $opts[CURLOPT_POSTFIELDS] = $params;
    } else {
      $opts[CURLOPT_POSTFIELDS] = http_build_query($params, null, '&');
    }
    $opts[CURLOPT_URL] = $url;

    // disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
    // for 2 seconds if the server does not support this header.
    if (isset($opts[CURLOPT_HTTPHEADER])) {
      $existing_headers = $opts[CURLOPT_HTTPHEADER];
      $existing_headers[] = 'Expect:';
      $opts[CURLOPT_HTTPHEADER] = $existing_headers;
    } else {
      $opts[CURLOPT_HTTPHEADER] = array('Expect:');
    }

    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);

    $errno = curl_errno($ch);
    // CURLE_SSL_CACERT || CURLE_SSL_CACERT_BADFILE
    if ($errno == 60 || $errno == 77) {
      self::errorLog('Invalid or no certificate authority found, '.
                     'using bundled information');
      curl_setopt($ch, CURLOPT_CAINFO,
                  dirname(__FILE__) . '/fb_ca_chain_bundle.crt');
      $result = curl_exec($ch);
    }

    // With dual stacked DNS responses, it's possible for a server to
    // have IPv6 enabled but not have IPv6 connectivity.  If this is
    // the case, curl will try IPv4 first and if that fails, then it will
    // fall back to IPv6 and the error EHOSTUNREACH is returned by the
    // operating system.
    if ($result === false && empty($opts[CURLOPT_IPRESOLVE])) {
        $matches = array();
        $regex = '/Failed to connect to ([^:].*): Network is unreachable/';
        if (preg_match($regex, curl_error($ch), $matches)) {
          if (strlen(@inet_pton($matches[1])) === 16) {
            self::errorLog('Invalid IPv6 configuration on server, '.
                           'Please disable or get native IPv6 on your server.');
            self::$curlOpts[CURLOPT_IPRESOLVE] = CURL_IPRESOLVE_V4;
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
            $result = curl_exec($ch);
          }
        }
    }

    if ($result === false) {
      $e = new EtalioApiException(array(
        'error_code' => curl_errno($ch),
        'error' => array(
        'message' => curl_error($ch),
        'type' => 'CurlException',
        ),
      ));
      curl_close($ch);
      throw $e;
    }
    curl_close($ch);
    return $result;
  }

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param $name string The name of the domain
   * @param $path string Optional path (without a leading slash)
   * @param $params array Optional query parameters
   *
   * @return string The URL for the given parameters
   */
  protected function getUrl($name, $params=array()) {
    $url = $this->domainMap[$name];
    if ($params) {
      $url .= '?' . http_build_query($params, null, '&');
    }
    return $url;
  }

  protected function getHttpHost() {
    return $_SERVER['HTTP_HOST'];
  }

  protected function getHttpProtocol() {
    return 'https';
  }

  /**
   * Get the base domain used for the cookie.
   */
  protected function getBaseDomain() {
    // The base domain is stored in the metadata cookie if not we fallback
    // to the current hostname
    $metadata = $this->getMetadataCookie();
    if (array_key_exists('base_domain', $metadata) &&
        !empty($metadata['base_domain'])) {
      return trim($metadata['base_domain'], '.');
    }
    return $this->getHttpHost();
  }

  /**
   * Returns the Current URL, stripping it of known ETALIO parameters that should
   * not persist.
   *
   * @return string The current URL
   */
  protected function getCurrentUrl() {
    $protocol = 'https://';
    $host = $this->getHttpHost();
    $currentUrl = $protocol.$host.$_SERVER['REQUEST_URI'];
    $parts = parse_url($currentUrl);

    $query = '';
    if (!empty($parts['query'])) {
      // drop known fb params
      $params = explode('&', $parts['query']);
      $retained_params = array();
      foreach ($params as $param) {
        if ($this->shouldRetainParam($param)) {
          $retained_params[] = $param;
        }
      }

      if (!empty($retained_params)) {
        $query = '?'.implode($retained_params, '&');
      }
    }

    // use port if non default
    $port =
      isset($parts['port']) && ($protocol === 'https://' && $parts['port'] !== 443)
      ? ':' . $parts['port'] : '';

    // rebuild
    return $protocol . $parts['host'] . $port . $parts['path'] . $query;
  }

  /**
   * Returns true if and only if the key or key/value pair should
   * be retained as part of the query string.  This amounts to
   * a brute-force search of the very small list of Etalio-specific
   * params that should be stripped out.
   *
   * @param string $param A key or key/value pair within a URL's query (e.g.
   *                     'foo=a', 'foo=', or 'foo'.
   *
   * @return boolean
   */
  protected function shouldRetainParam($param) {
    foreach (self::$DROP_QUERY_PARAMS as $drop_query_param) {
      if (strpos($param, $drop_query_param.'=') === 0) {
        return false;
      }
    }

    return true;
  }

  /**
   * Analyzes the supplied result to see if it was thrown
   * because the access token is no longer valid.  If that is
   * the case, then we destroy the session.
   *
   * @param $result array A record storing the error message returned
   *                      by a failed API call.
   */
  protected function throwAPIException($result) {
    $e = new EtalioApiException($result);
    switch ($e->getType()) {
      // OAuth 2.0 Draft 00 style
      case 'OAuthException':
        // OAuth 2.0 Draft 10 style
      case 'invalid_token':
        // REST server errors are just Exceptions
      case 'Exception':
        $message = $e->getMessage();
        if ((strpos($message, 'Error validating access token') !== false) ||
            (strpos($message, 'Invalid OAuth access token') !== false) ||
            (strpos($message, 'An active access token must be used') !== false)
        ) {
          $this->destroySession();
        }
        break;
    }

    throw $e;
  }


  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param string $msg Log message
   */
  protected static function errorLog($msg) {
    // disable error log if we are running in a CLI environment
    // @codeCoverageIgnoreStart
    if (php_sapi_name() != 'cli') {
      error_log($msg);
    }
    // uncomment this if you want to see the errors on the page
    // print 'error_log: '.$msg."\n";
    // @codeCoverageIgnoreEnd
  }

  /**
   * Base64 encoding that doesn't need to be urlencode()ed.
   * Exactly the same as base64_encode except it uses
   *   - instead of +
   *   _ instead of /
   *   No padded =
   *
   * @param string $input base64UrlEncoded string
   * @return string
   */
  protected static function base64UrlDecode($input) {
    return base64_decode(strtr($input, '-_', '+/'));
  }

  /**
   * Base64 encoding that doesn't need to be urlencode()ed.
   * Exactly the same as base64_encode except it uses
   *   - instead of +
   *   _ instead of /
   *
   * @param string $input string
   * @return string base64Url encoded string
   */
  protected static function base64UrlEncode($input) {
    $str = strtr(base64_encode($input), '+/', '-_');
    $str = str_replace('=', '', $str);
    return $str;
  }

  /**
   * Destroy the current session
   */
  public function destroySession() {
    $this->accessToken = null;
    $this->user = null;
    $this->clearAllPersistentData();

    // Javascript sets a cookie that will be used in getSignedRequest that we
    // need to clear if we can
    $cookie_name = $this->getSignedRequestCookieName();
    if (array_key_exists($cookie_name, $_COOKIE)) {
      unset($_COOKIE[$cookie_name]);
      if (!headers_sent()) {
        $base_domain = $this->getBaseDomain();
        setcookie($cookie_name, '', 1, '/', '.'.$base_domain);
      } else {
        // @codeCoverageIgnoreStart
        self::errorLog(
          'There exists a cookie that we wanted to clear that we couldn\'t '.
          'clear because headers was already sent. Make sure to do the first '.
          'API call before outputing anything.'
        );
        // @codeCoverageIgnoreEnd
      }
    }
  }

  /**
   * Parses the metadata cookie that our Javascript API set
   *
   * @return  an array mapping key to value
   */
  protected function getMetadataCookie() {
    $cookie_name = $this->getMetadataCookieName();
    if (!array_key_exists($cookie_name, $_COOKIE)) {
      return array();
    }

    // The cookie value can be wrapped in "-characters so remove them
    $cookie_value = trim($_COOKIE[$cookie_name], '"');

    if (empty($cookie_value)) {
      return array();
    }

    $parts = explode('&', $cookie_value);
    $metadata = array();
    foreach ($parts as $part) {
      $pair = explode('=', $part, 2);
      if (!empty($pair[0])) {
        $metadata[urldecode($pair[0])] =
          (count($pair) > 1) ? urldecode($pair[1]) : '';
      }
    }

    return $metadata;
  }

  protected static function isAllowedDomain($big, $small) {
    if ($big === $small) {
      return true;
    }
    return self::endsWith($big, '.'.$small);
  }

  protected static function endsWith($big, $small) {
    $len = strlen($small);
    if ($len === 0) {
      return true;
    }
    return substr($big, -$len) === $small;
  }

  /**
   * Each of the following four methods should be overridden in
   * a concrete subclass, as they are in the provided Etalio class.
   * The Etalio class uses PHP sessions to provide a primitive
   * persistent store, but another subclass--one that you implement--
   * might use a database, memcache, or an in-memory cache.
   *
   * @see Etalio
   */

  /**
   * Stores the given ($key, $value) pair, so that future calls to
   * getPersistentData($key) return $value. This call may be in another request.
   *
   * @param string $key
   * @param array $value
   *
   * @return void
   */
  abstract protected function setPersistentData($key, $value);

  /**
   * Get the data for $key, persisted by BaseEtalio::setPersistentData()
   *
   * @param string $key The key of the data to retrieve
   * @param boolean $default The default value to return if $key is not found
   *
   * @return mixed
   */
  abstract protected function getPersistentData($key, $default = false);

  /**
   * Clear the data with $key from the persistent storage
   *
   * @param string $key
   * @return void
   */
  abstract protected function clearPersistentData($key);

  /**
   * Clear all data from the persistent storage
   *
   * @return void
   */
  abstract protected function clearAllPersistentData();
}

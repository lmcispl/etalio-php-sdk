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
  const API_VERSION = "v1";

  /**
   * Version of this SDK
   */
  const VERSION = '0.2.1';

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
   * A CSRF state variable to assist in the defense against CSRF attacks.
   */
  protected $state;

  /**
   * The OAuth access token received in exchange for a valid authorization
   * code.  null means the access token has yet to be determined.
   */
  protected $accessToken;
  protected $refreshToken;
  protected $redirectUri;

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
    );
    $this->curlOpts = array(
      CURLOPT_CONNECTTIMEOUT => 10,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => 60,
      CURLOPT_USERAGENT      => 'etalio-php-'.self::VERSION,
      CURLOPT_VERBOSE        => $config['debug'],
    );
    $this->setRedirectUri($config['redirect_uri']);
    $this->setAppId($config['appId']);
    $this->setAppSecret($config['secret']);
    $state = $this->getPersistentData('state');
    $accessToken = $this->getPersistentData('access_token');
    $refreshToken = $this->getPersistentData('refresh_token');
    if (!empty($state)) {
      $this->state = $state;
    }
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
  public function getLoginUrl($params=[]) {
    $this->establishCSRFTokenState();
    // if 'scope' is passed as an array, convert to comma separated list
    $scopeParams = isset($params['scope']) ? $params['scope'] : null;
    if ($scopeParams && is_array($scopeParams)) {
      $params['scope'] = implode(',', $scopeParams);
    }

    return $this->getUrl(
      'oauth2',
      array_merge(
        array(
          'client_id'     => $this->appId,
          'state'         => $this->state,
          'redirect_uri'  => $this->redirectUri,
          'sdk'           => 'php-sdk-'.self::VERSION,
          'response_type' => 'code',
        ),
        $params
      ));
  }

  /**
   * AuthenticateUser, the main entry for the handshake
   */
  public function authenticateUser() {
    if(!isset($this->accessToken) && !isset($this->refresh_token)) {
      return $this->getAccessTokenFromCode();
    } elseif (isset($this->refreshToken)) {
      return $this->refreshAccessToken();
    }
    return $this->accessToken;
  }


  public function apiCall($path, $method = 'GET', $params = [], $headers = []) {
    if (is_array($method) && empty($params)) {
      $params = $method;
      $method = 'GET';
    }
    // json_encode all params values that are not strings
    foreach ($params as $key => $value) {
      if (!is_string($value)) {
        $params[$key] = json_encode($value);
      }
    }
    $result = json_decode($this->_oauthRequest(
      $this->getUrl($path, $params),
      $method,
      $headers
    ), true);

    // results are returned, errors are thrown
    if (is_array($result) && isset($result['error'])) {
      $this->throwAPIException($result);
    }
    var_dump($result);
    return $result;
  }

  /**
   * Set the Application ID.
   *
   * @param string $appId The Application ID
   * @return EtalioLoginBase
   */
  public function setAppId($appId) {
    $this->appId = $appId;
    return $this;
  }

  /**
   * Set the parameters that Curl will use
   * @param array $val The configuration options for curl
   * @return EtalioLoginBase
   */
  public function setCurlOpts($val) {
    $this->curlOpts = $val;
    return $this;
  }

  /**
   * Set the App Secret.
   *
   * @param string $appSecret The App Secret
   * @return EtalioLoginBase
   */
  public function setAppSecret($appSecret) {
    $this->appSecret = $appSecret;
    return $this;
  }

  /**
   * Set the redirect uri
   *
   * @param string $uri the redirect uri
   * @return EtalioLoginBase
   */
  public function setRedirectUri($uri) {
    $this->redirectUri = $uri;
    return $this;
  }

  /**
   * Determines the access token that should be used for API calls.
   *
   * @return string The access token
   */
  public function getAccessToken() {
    if($this->accessToken == null)
      return $this->getPersistentData('access_token');
    return $this->accessToken;
  }

  protected function setRefreshToken($token) {
    $this->refreshToken = $token;
    $this->setPersistentData('refresh_token',$token);
  }
  protected function setAccessToken($token) {
    $this->accessToken = $token;
    $this->setPersistentData('access_token',$token);
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
  protected function getAccessTokenFromCode() {
    $code = $this->getCodeFromRequest();
    if ($code && $code != $this->getPersistentData('code')) {
      $access_token = $this->requestAccessTokenFromCode($code);
      if ($access_token) {
        $this->setPersistentData('code', $code);
        $this->setPersistentData('access_token', $access_token);
        $this->accessToken = $access_token;
        return $access_token;
      }
      // code was bogus, so everything based on it should be invalidated.
      $this->clearAllPersistentData();
      return false;
    }
    return $this->accessToken;
  }


  /**
   * Get the authorization code from the query parameters, if it exists,
   * and otherwise return false to signal no authorization code was
   * discoverable.
   *
   * @return mixed The authorization code, or false if the authorization
   *               code could not be determined.
   */
  protected function getCodeFromRequest() {
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

  protected function requestAccessTokenFromCode($code) {
    if (empty($code)) {
      return false;
    }

    try {
      // need to circumvent json_decode by calling _oauthRequest
      // directly, since response isn't JSON format.
      $access_token_response =
        $this->makeRequest(
          $this->getUrl('token'),
          "POST",
          $params = [
                      'client_id' => $this->appId,
                      'client_secret' => $this->appSecret,
                      'redirect_uri' => $this->redirectUri,
                      'grant_type' => 'authorization_code',
                      'code' => $code,
                    ]
        );
    } catch (EtalioApiException $e) {
      // most likely that user very recently revoked authorization.
      // In any event, we don't have an access token, so say so.
      return false;
    }

    if (empty($access_token_response)) {
      return false;
    }

    $response_params = json_decode($access_token_response,true);
    $accessToken = $response_params['access_token'];
    if (!isset($accessToken)) {
      return false;
    }
    $this->setRefreshToken($response_params['refresh_token']);
    return $accessToken;
  }

  protected function refreshAccessToken() {
    try {
      // need to circumvent json_decode by calling _oauthRequest
      // directly, since response isn't JSON format.
      $access_token_response =
        $this->makeRequest(
          $this->getUrl('token'),
          $params = array(
            // 'client_id' => $this->appId,
            // 'client_secret' => $this->appSecret,
            // 'redirect_uri' => $this->redirectUri,
            'refresh_token' => $this->refreshToken,
            'grant_type' => 'refresh_token'));
    } catch (EtalioApiException $e) {
      // most likely that user very recently revoked authorization.
      // In any event, we don't have an access token, so say so.
      return false;
    }

    if (empty($access_token_response)) {
      return false;
    }

    $response_params = json_decode($access_token_response,true);
    $accessToken = $response_params['access_token'];
    if (!isset($accessToken)) {
      return false;
    }
    $this->setRefreshToken($response_params['refresh_token']);
    return $accessToken;
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
  protected function _oauthRequest($url, $method = "GET", $params = [], $headers = [], $ch = null) {
    if($this->getAccessToken() == null) {
      return false;
    }
    array_push($headers,"Authorization: Bearer ".$this->getAccessToken());
    return $this->makeRequest($url, $method, $params, $headers, $ch);
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
  protected function makeRequest($url, $method = "GET", $params = [], $headers=[], $ch=null) {
    if (!$ch) {
      $ch = curl_init();
    }
    $opts = $this->curlOpts;
    if($method == "POST") {
      $opts[CURLOPT_POSTFIELDS] = http_build_query($params, null, '&');
      $opts[CURLOPT_URL] = $url;
    } else {
      $opts[CURLOPT_URL] = $url.http_build_query($params, null, '&');
    }
    if (isset($opts[CURLOPT_HTTPHEADER])) {
      $opts[CURLOPT_HTTPHEADER] = array_merge($opts[CURLOPT_HTTPHEADER],$headers);
    } else {
      $opts[CURLOPT_HTTPHEADER] = $headers;
    }
    $opts[CURLOPT_CUSTOMREQUEST] = $method;
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
    var_dump($result);
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
    $this->refreshToken = null;
    $this->code = null;
    $this->user = null;
    $this->clearAllPersistentData();
    // Javascript sets a cookie that will be used in getSignedRequest that we
    // need to clear if we can
    // $cookie_name = $this->getSignedRequestCookieName();
    // if (array_key_exists($cookie_name, $_COOKIE)) {
    //   unset($_COOKIE[$cookie_name]);
    //   if (!headers_sent()) {
    //     $base_domain = $this->getBaseDomain();
    //     setcookie($cookie_name, '', 1, '/', '.'.$base_domain);
    //   } else {
    //     // @codeCoverageIgnoreStart
    //     self::errorLog(
    //       'There exists a cookie that we wanted to clear that we couldn\'t '.
    //       'clear because headers was already sent. Make sure to do the first '.
    //       'API call before outputing anything.'
    //     );
    //     // @codeCoverageIgnoreEnd
    //   }
    // }
  }

  protected function getMetadataCookieName() {
    return 'etalio_'.$this->getAppId();
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

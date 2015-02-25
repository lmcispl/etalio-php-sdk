<?php
namespace Mdi\Auth\Mc;

use Etalio\EtalioApiException;
use Etalio\EtalioBase;
use Exception;

class Authenticator extends EtalioBase {

  // We can set this to a high number because the main session
  // expiration will trump this.
  const ACCESS_TOKEN = 'access_token';
  const ACCESS_TOKEN_EXPIRATION_TIME = 'access_token_expiration_time';
  const AUTH_URL = 'auth_url';
  const CLIENT_ID = 'appId';
  const CLIENT_SECRET = 'client_secret';
  const ETALIOSS_COOKIE_EXPIRE = 31556926; // 1 year
  const NONCE = 'nonce';
  const REDIRECT_URI = 'redirect_uri';
  const REFRESH_TOKEN = 'refresh_token';
  const STATE = 'state';
  const TOKEN_URL = 'token_url';
  const USERINFO_URL = 'userinfo_url';
  const SCOPE = 'scope';
  const COUNTRY = 'country';
  const CURRENCY = 'currency';
  const SUBSCRIBER_ID = 'subscriber_id';
  const MDI_BACKEND = 'mdi_backend';
  const PCR = 'pcr';

  // Keys we support to store in the persistent data
  protected static $kSupportedKeys = array(
    self::MDI_BACKEND,
    self::STATE,
    self::NONCE,
    self::ACCESS_TOKEN,
    self::REFRESH_TOKEN,
    self::ACCESS_TOKEN_EXPIRATION_TIME,
    self::AUTH_URL,
    self::TOKEN_URL,
    self::USERINFO_URL,
    self::CLIENT_ID,
    self::CLIENT_SECRET,
    self::REDIRECT_URI,
    self::COUNTRY,
    self::CURRENCY,
    self::SUBSCRIBER_ID,
    self::SCOPE,
    self::PCR
  );

  /**
   * Identical to the parent constructor, except that
   * we start a PHP session to store the user ID and
   * access token if during the course of execution
   * we discover them.
   * @see EtalioApi::__construct in etalio_api.php
   * @param array $config
   */
  public function __construct(Array $config = []) {
    if (!session_id()) {
      session_start();
    }
    $config['appId'] = $this->getPersistentData(self::CLIENT_ID);
    $config['secret'] = $this->getPersistentData(self::CLIENT_SECRET);
    parent::__construct($config);

    $this->createDomainMap();
  }

  private function createDomainMap() {
    $this->domainMap = array(
      'oidc' => $this->getPersistentData(self::AUTH_URL),
      'token' => $this->getPersistentData(self::TOKEN_URL),
      'userinfo' => $this->getPersistentData(self::USERINFO_URL)
    );
  }

  public function loadDiscovery(DiscoveryDataParser $data) {
    $this->setPersistentData(self::CLIENT_ID, $data->getClientId());
    $this->setAppId($data->getClientId());

    $this->setPersistentData(self::AUTH_URL, $data->findAuthorizationUrl());
    $this->setPersistentData(self::USERINFO_URL, $data->findUserinfoUri());
    $this->setPersistentData(self::TOKEN_URL, $data->findTokenUri());
    $this->setPersistentData(self::CLIENT_SECRET, $data->getClientSecret());
    $this->setPersistentData(self::COUNTRY, $data->getCountry());
    $this->setPersistentData(self::CURRENCY, $data->getCurrency());
    $this->setPersistentData(self::SUBSCRIBER_ID, $data->getSubscriberId());

    $this->createDomainMap();
    $this->setAppDetails();
  }

  private function setAppDetails(){
    $this->setAppSecret($this->getPersistentData(self::CLIENT_SECRET));
    $this->setRedirectUri($this->getPersistentData(self::REDIRECT_URI));
  }
  public function isDiscoveryLoaded() {
    $url = $this->getPersistentData(self::TOKEN_URL);
    return !empty($url);
  }

  public function getUserinfo(){
    $res = $this->apiCall('userinfo');
    return $res;
  }

  /** Gets the PCR for the user.
   * This information comes from the id_token and should always be set
   */
  public function getUserId() {
    return $this->getPersistentData(self::PCR);
  }

  /**
   * Set the PCR
   * @param string $sub
   */
  private function setUserId($sub) {
    $this->setPersistentData(self::PCR, $sub);
  }

  /**
   * Requests to exchange the OAuth code for access and refresh_token
   * Stores both values using their setters
   *
   * @param string $code The code from an oauth handshake
   * @return mixed false or the access_token
   * @throws \Exception
   */
  protected function requestAccessTokenFromCode($code) {
    $this->debug("Requesting access_token from code");
    if ($this->isEmptyString([$code,$this->appId,$this->appSecret])) {
      $this->debug("Code, AppId or AppSecret is empty, can not request code.");
      return false;
    }

    try {
      // need to circumvent json_decode by calling makeRequest
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
      // In any event, we don't have an access_token, so say so.
      $this->debug("Token url responded with an error");
      return false;
    }

    if (empty($access_token_response)) {
      $this->debug("The access_token response was empty");
      return false;
    }
    $response_params = json_decode($access_token_response,true);

    if (!isset($response_params['access_token']) || !isset($response_params['token_type'])) {
      $this->debug("One of access_token, id_token, and token_type is not part of the response");
      return false;
    }
    $this->setAccessToken($response_params['access_token']);

    if (isset($response_params['id_token'])) {
      $this->validateToken($response_params['id_token']);
    }

    if (isset($response_params['refresh_token'])) {
      $this->setRefreshToken($response_params['refresh_token']);
    }

    if (isset($response_params['expires_in']))
      $this->setAccessTokenExpirationTime($response_params['expires_in'] + time());

    return $response_params['access_token'];
  }

  private function validateToken($idToken){
    list($algJson, $payloadJson, $sign) = explode('.', $idToken);
    $token_data = json_decode(base64_decode($payloadJson),true);
    $this->errorLog("Token data".json_encode($token_data));
    $this->setAccessTokenExpirationTime($token_data['exp']);

    if ($token_data['iss'] === 'https://api.etalio.com')
      $this->setMdiBackend(true);
    if (array_key_exists('sub', $token_data))
      $this->setUserId($token_data['sub']);
    $nonce = $this->getPersistentData(self::NONCE);
    if ($nonce !== $token_data[self::NONCE]){
      $this->debug(
        sprintf(
          'The nonce did not match the expected. Was: %s, expected: %s', $token_data[self::NONCE], $nonce));
      return false;
    }

    if ($token_data['aud'] !== $this->appId) {
      $this->debug("The id_token was not intended for us");
      return false;
    }

    return true;
  }

  public function isAccessTokenAvailable(){
    return $this->getPersistentData(self::ACCESS_TOKEN, false);
  }

  public function getLoginUrl(Array $params = []) {
    if (!isset($params['scope']))
      $params['scope'] = $this->getPersistentData(self::SCOPE);
    return parent::getLoginUrl($params);
  }

  public function revokeToken() {
    // This is not supported in MC
    return null;
  }

  /**
   * Provides the implementations of the inherited abstract
   * methods.  The implementation uses PHP sessions to maintain
   * a store for CSRF states, refresh tokens and access tokens.
   *
   * Stores the given ($key, $value) pair, so that future calls to
   * getPersistentData($key) return $value. This call may be in another request.
   *
   * @param string $key
   * @param array $value
   *
   * @return void
   */
  protected function setPersistentData($key, $value) {
    $this->debug("Setting persistent data: ".$key.":".$value);
    if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to setPersistentData: '.$key.$value);
      return;
    }
    $session_var_name = $this->constructSessionVariableName($key);
    $_SESSION[$session_var_name] = $value;
  }

  /**
   * Get the data for $key, persisted by BaseEtalio::setPersistentData()
   *
   * @param string $key The key of the data to retrieve
   * @param boolean $default The default value to return if $key is not found
   *
   * @return mixed
   */
  protected function getPersistentData($key, $default = false) {
    if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to getPersistentData: '.$key);
      return $default;
    }
    $session_var_name = $this->constructSessionVariableName($key);
    $val = isset($_SESSION[$session_var_name]) ? $_SESSION[$session_var_name] : $default;
    $this->debug("Reading persistent data: ".$session_var_name.":".$key.":".$val);
    return $val;
  }

  /**
   * Clear the data with $key from the persistent storage
   *
   * @param string $key
   * @return void
   */
  protected function clearPersistentData($key) {
    $this->debug("Clearing persistent data: ".$key);
    if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to clearPersistentData: '.$key);
      return;
    }

    $session_var_name = $this->constructSessionVariableName($key);
    if (isset($_SESSION[$session_var_name])) {
      unset($_SESSION[$session_var_name]);
    }
  }

  /**
   * Clear all data from the persistent storage
   *
   * @return void
   */
  protected function clearAllPersistentData() {
    foreach (self::$kSupportedKeys as $key) {
      $this->clearPersistentData($key);
    }
  }

  protected function constructSessionVariableName($key) {
    return implode('_', ['mdi', $this->appId, $key]);
  }

  private function setMdiBackend($mdi) {
    $this->setPersistentData(self::MDI_BACKEND, $mdi);
  }

  private function isMdiBackend(){
    return $this->getPersistentData(self::MDI_BACKEND);
  }
}

<?php
/**
 * Copyright 2014 Ericsson AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

namespace Etalio;
require_once "etalio_base.php";

/**
 * Extends the EtalioLogin class and adds helper methods for the Etalio Api
 */
abstract class EtalioApi extends EtalioBase
{

  /**
   * APi version
   */
  const API_VERSION = "v1";

  protected $baseUrlApi = "https://api.etalio.com";

  protected $currentProfile;
  protected $userInfo;

  /**
   * Identical to the parent constructor, except that
   * we start a PHP session to store the user ID and
   * access token if during the course of execution
   * we discover them.
   * @see EtalioBase::__construct in etalio_base.php
   */
  public function __construct(Array $config = []) {
    parent::__construct($config);
    if(isset($config['baseUrlApi'])) $this->setBaseUrlApi($config['baseUrlApi']);

    $this->createDomainMap();
  }

  protected function createDomainMap(){
    $this->domainMap = array_merge($this->domainMap, [
      'myprofile'                  => $this->baseUrlApi . '/' . self::API_VERSION . '/profile/me',
      'userinfo'                   => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/userinfo',
      'profiles'                   => $this->baseUrlApi . '/' . self::API_VERSION . '/profiles',
      'profile'                    => $this->baseUrlApi . '/' . self::API_VERSION . '/profile',
      'profileClaim'               => $this->baseUrlApi . '/' . self::API_VERSION . '/profile/claim',
      'profileApplications'        => $this->baseUrlApi . '/' . self::API_VERSION . '/profile',
      'application'                => $this->baseUrlApi . '/' . self::API_VERSION . '/application',
      'applications'               => $this->baseUrlApi . '/' . self::API_VERSION . '/applications',
      'applicationKeys'            => $this->baseUrlApi . '/' . self::API_VERSION . '/applications',
      'categories'                 => $this->baseUrlApi . '/' . self::API_VERSION . '/categories',
      'scopes'                     => $this->baseUrlApi . '/' . self::API_VERSION . '/scopes',
      'msisdn'                     => $this->baseUrlApi . '/' . self::API_VERSION . '/msisdn',
      'msisdnClaim'                => $this->baseUrlApi . '/' . self::API_VERSION . '/msisdn/claim',
      'netops'                     => $this->baseUrlApi . '/' . self::API_VERSION . '/netops',
      'resetPassword'              => $this->baseUrlApi . '/' . self::API_VERSION . '/profile/password-reset',
      'verifyResetPassword'        => $this->baseUrlApi . '/' . self::API_VERSION . '/profile/password/reset',
      'token'                      => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/token',
      'authorize'                  => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/authorize',
      'revoke'                     => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/revoke',
      'oidc-authorize'             => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/authorize',
      'oidc-ape'                   => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/ape',
      'oidc-auth-sms'              => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/authenticate/sms',
      'oidcAuthenticateSms'        => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/authenticate/sms',
      'oidcAuthenticateSmsConfirm' => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/authenticate/sms/confirm',
      'oidcAuthenticateStatus'     => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/authenticate/status',
      'oidcAuthenticateLoa3'       => $this->baseUrlApi . '/' . self::API_VERSION . '/oauth2/oidc/authenticate/loa3',
    ]);
  }

  public function setBaseUrlApi($baseUrlApi) {
    $this->baseUrlApi = $baseUrlApi;
    return $this;
  }

  public function isAuthenticated(){
    return $this->isAccessTokenExpired();
  }

  public function authenticateSms(Array $data){
    $status = $this->apiCall('oidc-auth-sms', 'POST', $data, [ parent::JSON_CONTENT_TYPE ]);
    if(is_array($status))
      return $status;
    return false;
  }

  public function handleMsisdn(Array $data){
    $status = $this->apiCall('msisdn', 'POST', $data, [ parent::JSON_CONTENT_TYPE ]);
    if(is_array($status))
      return $status;
    return false;
  }

  public function claimMsisdn(Array $data){
    $status = $this->apiCall('msisdnClaim', 'POST', $data, [ parent::JSON_CONTENT_TYPE ]);
    if(is_array($status))
      return $status;
    return false;
  }

  public function smsMT($msisdn) {
    //Send verification code
    $params = array(
      'msisdn' => $msisdn,
      'requestCode' => true,
    );

    return $this->handleMsisdn($params);
  }

  public function smsMTCode($msisdn, $code) {
    //Send verification code
    $params = array(
      'msisdn' => $msisdn,
      'requestCode' => strtoupper($code),
    );

    return $this->handleMsisdn($params);
  }

  /**
   * Will send an authentication sms to the msisdn
   *
   * The user will need to be registered, and the the access token must come from a
   * trusted application
   *
   * @param $msisdn
   * @return mixed the json response as an array
   */
  public function oidcAuthenticateSms($msisdn){
    $data = ['msisdn' => $msisdn];
    return $this->apiCall('oidcAuthenticateSms', 'POST', $data, [ parent::JSON_CONTENT_TYPE ]);
  }


  /**
   * Checks the status for the current authentication process
   *
   * The user will need to be registered, and the the access token must come from a
   * trusted application
   *
   * @return mixed the json response as an array
   */
  public function oidcAuthenticateStatus(){
    return $this->apiCall('oidcAuthenticateStatus');
  }

  /**
   * Uploads the status code delivered by sms in `oidcAuthenticateSms`
   *
   * This call is only available to trusted applications
   *
   * @param $code string the code sent to the device
   * @return mixed the json response as an array
   */
  public function oidcAuthenticateSmsConfirm($code){
    return $this->apiCall('oidcAuthenticateSmsConfirm', 'POST', ['code' => $code], [parent::JSON_CONTENT_TYPE]);
  }

  /**
   * Authorize an app or redirect to grant application
   */
  public function authorizeApp(Array $params = []){
    $this->debug('Authorize app');
    if (!isset($params['client_id'])) {
      $this->debug('Fail to authorize app: No Application Client Key');
      return false;
    } elseif (!isset($params['state'])) {
      $this->debug('Fail to authorize app: No Application Client State');
      return false;
    } elseif (!isset($params['redirect_uri'])) {
      $this->debug('Fail to authorize app: No Application Client Redirect URI');
      return false;
    }

    if ($this->isEmptyString($this->accessToken)) {
      $this->authenticateUser();
    }
    return $this->apiCall('authorize', 'POST', $params, [ self::JSON_CONTENT_TYPE ]);
  }

  /**
   * Authorize an app or redirect to grant application
   */
  public function authorizeOidcApp(Array $params = []){
    $this->debug('Authorize app');
    if (!isset($params['client_id'])) {
      $this->debug('Fail to authorize app: No Application Client Key');
      return false;
    } elseif (!isset($params['state'])) {
      $this->debug('Fail to authorize app: No Application Client State');
      return false;
    } elseif (!isset($params['redirect_uri'])) {
      $this->debug('Fail to authorize app: No Application Client Redirect URI');
      return false;
    }

    if ($this->isEmptyString($this->accessToken)) {
      $this->authenticateUser();
    }
    return $this->apiCall('oidc-authorize', 'POST', $params, [ self::JSON_CONTENT_TYPE ]);
  }

  /**
   * Starts the authentication for loa 3.
   *
   * The first factor is always password, and the second factor can be sms, ussd, push, etc.
   *
   * @param $msisdn string
   * @param $password string
   * @param $secondary string
   * @return bool|mixed status if success, otherwise false
   *
   * @see https://developer.etalio.com/docs/OAuth2_OpenID_Connect_authenticate_loa3.html
   */
  public function authenticateLoa3($msisdn, $password, $secondary){
    $status = $this->apiCall('oidcAuthenticateLoa3', 'POST', [
      'msisdn' => $msisdn,
      'password' => $password,
      'secondary' => $secondary,
    ], [self::JSON_CONTENT_TYPE]);
    if(is_array($status))
      return $status;
    return false;
  }

  public function profileClaim(Array $params) {
    $status = $this->apiCall('profileClaim', 'POST', $params, [ parent::JSON_CONTENT_TYPE ]);
    if(is_array($status))
      return $status;
    return false;
  }

  public function getNetopsForHni($hni){
    $res = $this->apiCall('netops', 'GET', array('hni' => $hni), [ parent::JSON_CONTENT_TYPE ]);
    if(is_array($res))
      return $res;
    return false;
  }

  public function getNetops($msisdn = ''){
    if (isset($msisdn) && $msisdn) {
      $res = $this->apiCall('netops', 'GET', array('msisdn' => $msisdn), [ parent::JSON_CONTENT_TYPE ]);
    } else {
      $res = $this->apiCall('netops', 'GET');
    }

    if(is_array($res))
      return $res;
    return false;
  }

  public function getNetop($id){
    $key = 'netop'.$id;
    $url = $this->domainMap['netops']."/" . $id;
    $this->setDomainPath($key, $url);
    $res = $this->apiCall($key, 'GET');
    if(is_array($res))
      return $res;
    return false;
  }

  public function getNetopEula($id){
    $key = 'netop'.$id;
    $url = $this->domainMap['netops']."/" . $id . "/eula";
    $this->setDomainPath($key, $url);
    $res = $this->apiCall($key, 'GET');
    if(is_array($res))
      return $res;
    return false;
  }

  //Endpoint for just POST
  public function resetPassword(Array $params) {
    return $this->apiCall('resetPassword', 'POST', $params, [ parent::JSON_CONTENT_TYPE ]);
  }

  public function verifyResetPassword(Array $params, $method = 'GET') {
    return $this->apiCall('verifyResetPassword', $method, $params, [ parent::JSON_CONTENT_TYPE ]);
  }

  public function getCurrentProfile(){
    if(!isset($this->currentProfile)) {
      $profile = $this->apiCall('myprofile');
      if($profile && (isset($profile['id']) || isset($profile['sub']))) {
        $this->currentProfile = $profile;
      } else {
        return false;
      }
    }
    return (Array)$this->currentProfile;
  }

  public function getUserinfo(){
    if (!isset($this->userInfo)){
      $profile = $this->apiCall('userinfo');
      if ($profile && isset($profile['sub'])) {
        $this->userInfo = $profile;
      } else {
        return false;
      }
    }
    return (Array) $this->userInfo;
  }

  public function updateCurrentProfile(Array $profile){
    return $this->apiCall('myprofile', 'PUT', $profile, [parent::JSON_CONTENT_TYPE]);
  }

  public function getCurrentProfileApplications(){

  }

  public function deleteCurrentProfileApplication($applicationId){

  }

  public function verifyEmail($user_id, $payload){
    $this->setDomainPath('profile-' . $user_id . '-email-verify', $this->domainMap['profile']."/" . $user_id . "/email-verify");
    $status = $this->apiCall('profile-' . $user_id . '-email-verify', 'POST', $payload, [parent::JSON_CONTENT_TYPE]);
    if($status && isset($status['status'])) {
      return $status;
    }
    return false;
  }

  public function getProfiles(){
    $profiles = $this->apiCall('profiles');
    if($profiles && is_array($profiles)) {
      return $profiles;
    }
    return false;
  }

  public function getProfile($profileId){
    $this->setDomainPath('profile-'.$profileId, $this->domainMap['profile']."/".$profileId);
    $profile = $this->apiCall('profile-'.$profileId);
    if($profile && isset($profile['id'])) {
      return $profile;
    }
    return false;
  }

  public function createProfile($payload){
    $profile = $this->apiCall('profiles', "POST", $payload, [ parent::JSON_CONTENT_TYPE ]);
    if($profile && isset($profile['id'])){
      return $profile;
    }
    return false;
  }

  public function deleteProfile($profileId){
    $this->setDomainPath('delete-profile-'.$profileId, $this->domainMap['profile']."/".$profileId);
    $res = $this->apiCall('delete-profile-'.$profileId, 'DELETE');
    if($res === NULL){
      return true;
    }
    return false;
  }

  public function updateProfile($profileId, $payload){
    $identifier = 'profile-'.$profileId;
    $this->setDomainPath($identifier, $this->domainMap['profile']."/".$profileId);
    $profile = $this->apiCall($identifier, "PUT", $payload, [ parent::JSON_CONTENT_TYPE ]);
    if($profile && isset($profile['id'])){
      return $profile;
    }
    return false;
  }

  public function setProfileImage($profileId, $imagePath, $imageType, $imageName){
    $imageDomainPath = 'profile-'.$profileId.'-image';
    $this->setDomainPath($imageDomainPath, $this->domainMap['profile'].'/'.$profileId.'/image');
    $files = [];
    if(class_exists("CURLFile")){
      // If > PHP5.5
      $files['image'] = new \CURLFile($imagePath, $imageType, 'image');
    }else{
      // PHP5.4
      $files['image'] = "@".$imagePath.";type=".$imageType.";";
    }
    $res = $this->apiCall($imageDomainPath, "POST", [], [], $files);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function getProfileImage($profileId, $size){
    $imageDomainPath = 'profile-'.$profileId.'-image';
    $this->setDomainPath($imageDomainPath, $this->domainMap['profile'].'/'.$profileId.'/image');
    $res = $this->apiCall($imageDomainPath, "GET", ['size' => $size]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function updateGrantByProileAndClientIdAndScope($profileId, $keyId, $scope){
    $updateDomainPath = 'update-profile-'.$profileId.'-revoke-grant-'.$keyId;
    $this->setDomainPath($updateDomainPath, $this->domainMap['profile'].'/'.$profileId.'/grant/'.$keyId);
    $grant = $this->apiCall($updateDomainPath, "PUT", ['scope' => $scope], [ parent::JSON_CONTENT_TYPE ]);
    if($grant && isset($grant)){
      return $grant;
    }
    return false;
  }

  public function grantApplicationByProfile($profileId, $key, $scope) {
    $grantDomainPath = 'profile-'.$profileId.'-grant-application';
    $this->setDomainPath($grantDomainPath, $this->domainMap['profile'].'/'.$profileId.'/grants');
    $res = $this->apiCall($grantDomainPath, 'POST', ['key' => $key, 'scope' => $scope], [ parent::JSON_CONTENT_TYPE ]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function revokeGrantByProfile($profileId, $keyId){
    $revokeDomainPath = 'profile-'.$profileId.'-revoke-grant-'.$keyId;
    $this->setDomainPath($revokeDomainPath, $this->domainMap['profile'].'/'.$profileId.'/grant/'.$keyId);
    $res = $this->apiCall($revokeDomainPath, 'DELETE');
    if($res === NULL){
      return true;
    }
    return false;
  }

  public function getGrantByProfileIdAndClientId($profileId, $clientId){
    $grantPath = 'profile-'.$profileId.'-grant-application-'.$clientId;
    $this->setDomainPath($grantPath, $this->domainMap['profile'].'/'.$profileId.'/grant/'.$clientId);
    $res = $this->apiCall($grantPath, 'GET', [], [ parent::JSON_CONTENT_TYPE ]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function revokeApplicationByProfile($profileId, $appId) {
    $revokeDomainPath = 'profile-'.$profileId.'-revoke-application-'.$appId;
    $this->setDomainPath($revokeDomainPath, $this->domainMap['profile'].'/'.$profileId.'/application/'.$appId);
    $res = $this->apiCall($revokeDomainPath, 'DELETE');
    if($res === NULL){
      return true;
    }
    return false;
  }

  public function getProfileApplications($profileId){

  }

  public function getApplications($authorUuid = NULL, $extra = array() ){
    $data = array('author' => $authorUuid);
    if (count($extra) > 0){
      $data = array_merge($data, $extra);
    }
    $apps = $this->apiCall('applications', $data);
    if(is_array($apps))
      return $apps;
    return false;
  }


  public function getApplication($id){
    $this->setDomainPath('application-'.$id, $this->domainMap['application']."/".$id);
    $application = $this->apiCall('application-'.$id);
    if($application && isset($application['id'])) {
      return $application;
    }
    return false;
  }

  public function createApplication($payload){
    $application = $this->apiCall('applications', "POST", $payload, [ parent::JSON_CONTENT_TYPE ]);
    if($application && isset($application)){
      return $application;
    }
    return false;
  }

  public function updateApplication($id, $payload){
    $this->setDomainPath('application-'.$id, $this->domainMap['application']."/".$id);
    $application = $this->apiCall('application-'.$id, "PUT", $payload, [ parent::JSON_CONTENT_TYPE ]);
    if($application && isset($application)){
      return $application;
    }
    return false;
  }

  /**
   * Deletes the application
   *
   * @param id the application to delete
   */
  public function deleteApplication($id){
    $this->setDomainPath('application-'.$id, $this->domainMap['application']."/".$id);
    $res = $this->apiCall('application-'.$id, "DELETE");
    if($res === NULL){
      return true;
    }
    return false;
  }

  public function setApplicationImage($applicationId, $imagePath, $imageType, $imageName){
    $imageDomainPath = 'application-'.$applicationId.'-image';
    $this->setDomainPath($imageDomainPath, $this->domainMap['application'].'/'.$applicationId.'/image');
    $files = [];
    if(class_exists("CURLFile")){
      // If PHP5.5 <
      $files['image'] = new \CURLFile($imagePath, $imageType, 'image');
    }else{
      // PHP5.4
      $files['image'] = "@".$imagePath.";type=".$imageType.";";
    }
    $res = $this->apiCall($imageDomainPath, "POST", [], [], $files);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function getApplicationImage($applicationId, $size){
    $imageDomainPath = 'application-'.$applicationId.'-image';
    $this->setDomainPath($imageDomainPath, $this->domainMap['application'].'/'.$applicationId.'/image');
    $res = $this->apiCall($imageDomainPath, "GET", ['size' => $size]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function deleteApplicationImage($applicationId){

  }

  public function setApplicationFeaturedImage($applicationId, $imagePath, $imageType, $imageName){
    $imageDomainPath = 'application-'.$applicationId.'-featured-image';
    $this->setDomainPath($imageDomainPath, $this->domainMap['application'].'/'.$applicationId.'/featuredImage');
    $files = [];
    if(class_exists("CURLFile")){
      // If PHP5.5 <
      $files['image'] = new \CURLFile($imagePath, $imageType, 'image');
    }else{
      // PHP5.4
      $files['image'] = "@".$imagePath.";type=".$imageType.";";
    }
    $res = $this->apiCall($imageDomainPath, "POST", [], [], $files);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function getApplicationFeaturedImage($applicationId, $size){
    $imageDomainPath = 'application-'.$applicationId.'-image';
    $this->setDomainPath($imageDomainPath, $this->domainMap['application'].'/'.$applicationId.'/image');
    $res = $this->apiCall($imageDomainPath, "GET", ['size' => $size]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function getApplicationKey($applicationId, $keyId){

  }

  public function createApplicationKey($id, $payload){
    $keyDomainPath = 'application-'.$id.'-keys';
    $this->setDomainPath($keyDomainPath, $this->domainMap['application'].'/'.$id.'/keys');
    $res = $this->apiCall($keyDomainPath, "POST", $payload, [ parent::JSON_CONTENT_TYPE ]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function updateApplicationKey($applciationId, $keyId, $payload){
    $keyDomainPath = 'application-'.$applciationId.'-keys';
    $this->setDomainPath($keyDomainPath, $this->domainMap['application'].'/'.$applciationId.'/key/'.$keyId);
    $res = $this->apiCall($keyDomainPath, "PUT", $payload, [ parent::JSON_CONTENT_TYPE]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function deleteApplicationKey($applicationId, $keyId){
    $path = 'application-'.$applicationId."-key-".$keyId;
    $this->setDomainPath($path, $this->domainMap['application']."/".$applicationId."/key/".$keyId);
    $res = $this->apiCall($path, "DELETE");
    if($res === NULL){
      return true;
    }
    return false;
  }

  public function getApplicationKeys($id){
    $this->setDomainPath('application-keys-'.$id, $this->domainMap['application']."/".$id."/keys");
    $keys = $this->apiCall('application-keys-'.$id);
    if(is_array($keys)) {
      return $keys;
    }
    return false;
  }

  /**
   * Get list of categories
   * @return array list of categories
   */
  public function getCategories(){
    $categories = $this->apiCall('categories');
    if(isset($categories) && is_array($categories))
      return $categories;
    return false;
  }

  /**
   * Get list of scopes
   * @return array list of scopes
   */
  public function getScopes(){
    $scopes = $this->apiCall('scopes');
    if(isset($scopes) && is_array($scopes))
      return $scopes;
    return false;
  }

  public function doSignin($payload){
    $res = $this->apiCall('token', "POST", $payload, [ parent::JSON_CONTENT_TYPE ]);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function getLoa($msisdn, $method = 'GET'){
    if (isset($msisdn) && $msisdn) {
      $res = $this->apiCall('oidc-ape', $method, array('msisdn' => $msisdn), [ parent::JSON_CONTENT_TYPE ]);
    } else {
      return false;
    }

    if(is_array($res))
      return $res;
    return false;
  }

  private function setDomainPath($key,$value) {
    $this->domainMap = array_merge($this->domainMap, [
      $key => $value,
    ]);
  }
}
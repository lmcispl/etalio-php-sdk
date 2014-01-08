<?php
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

  protected $currentProfile;

  /**
   * Identical to the parent constructor, except that
   * we start a PHP session to store the user ID and
   * access token if during the course of execution
   * we discover them.
   * @see EtalioBase::__construct in etalio_base.php
   */
  public function __construct(Array $config = []) {
    parent::__construct($config);
    $this->createDomainMap();
  }

  protected function createDomainMap(){
    $this->domainMap = array_merge($this->domainMap, [
      'myprofile'           => self::BASE_URL . '/' . self::API_VERSION . '/profile/me',
      'profiles'            => self::BASE_URL . '/' . self::API_VERSION . '/profiles',
      'profile'             => self::BASE_URL . '/' . self::API_VERSION . '/profile',
      'profileApplications' => self::BASE_URL . '/' . self::API_VERSION . '/profile',
      'application'         => self::BASE_URL . '/' . self::API_VERSION . '/application',
      'applications'        => self::BASE_URL . '/' . self::API_VERSION . '/applications',
      'applicationKeys'     => self::BASE_URL . '/' . self::API_VERSION . '/applications',

    ]);
  }

  public function isAuthenticated(){
    return ($this->getCurrentProfile())?true:false;
  }

  public function getCurrentProfile(){
    if(!isset($this->currentProfile)) {
      $profile = $this->apiCall('myprofile');
      if($profile && isset($profile['id'])) {
        $this->currentProfile = $profile;
      } else {
        return false;
      }
    }
    return (Array)$this->currentProfile;
  }

  public function updateCurrentProfile(Array $profile){
    return $this->apiCall('myprofile','PUT',$profile);
  }

  public function getCurrentProfileApplications(){

  }

  public function deleteCurrentProfileApplication($applicationId){

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
    $profile = $this->apiCall('profile', "POST", $payload, [ parent::JSON_CONTENT_TYPE ]);
    if($profile && isset($profile['id'])){
      return $profile;
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

  public function getProfileApplications($profileId){

  }

  public function getApplications(){
    $apps = $this->apiCall('applications');
    if(isset($apps) && is_array($apps))
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
    $this->setDomainPath($imageDomainPath, $this->domainMap['application'].'/'.$applicationId.'/images');
    $files = [];
    $files[] = new \CurlFile($imagePath, $imageType, $imageName);
    $res = $this->apiCall($imageDomainPath, "POST", [], ['Content-Type: image/*'], $files);
    if($res && isset($res)){
      return $res;
    }
    return false;
  }

  public function deleteApplicationImage($applicationId){

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

  private function setDomainPath($key,$value) {
    $this->domainMap = array_merge($this->domainMap, [
      $key => $value,
    ]);
  }
}
?>
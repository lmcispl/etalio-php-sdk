<?php
namespace Etalio;
require_once "etalio_login.php";
require_once "models/profile.php";

/**
 * Extends the EtalioLogin class and adds helper methods for the Etalio Api
 */
class Etalio extends EtalioLogin
{
  protected $currentProfile;

  public function __construct($config) {
    parent::__construct($config);
    $this->domainMap = array_merge($this->domainMap, [
      'myprofile'   => self::BASE_URL . '/' . self::API_VERSION . '/profile/me',
      'profile'   => self::BASE_URL . '/' . self::API_VERSION . '/profile',
      'apps'      => self::BASE_URL . '/' . self::API_VERSION . '/user/applications',
    ]);
  }

  public function isProfileAuthenticated(){
    return $this->getCurrentProfile() != null;
  }

  public function getApplications($userId){

  }

  public function getApplication($id){

  }

  public function createApplication($payload){

  }

  public function updateApplication($applicationId, $payload){

  }

  public function deleteApplication($applicationId){

  }

  public function setApplicationImage($applicationId, $image){

  }

  public function deleteApplicationImage($applicationId){

  }

  public function getApplicationKey($applicationId, $keyId){

  }

  public function createApplicationKey($applicationId){

  }

  public function updateApplicationKey($applciationId, $keyId, $payload){

  }

  public function deleteApplicationKey($applicationId, $keyId){

  }

  public function getApplicationKeys($applicationId){

  }

  public function getCurrentProfile(){
    if(!isset($this->currentProfile)) {
      $this->currentProfile = new \Etalio\Models\Profile($this->apiCall('myprofile'));
    }
    return $this->currentProfile;
  }

  public function updateCurrentProfile(){

  }

  public function getCurrentProfileApplications(){

  }

  public function deleteCurrentProfileApplication($applicationId){

  }

  public function getProfile($profileId){
    $this->domainMap = array_merge($this->domainMap, [
      'profile-'.$profileId   => $this->domainMap['profile']."/".$profileId,
    ]);
    return new \Etalio\Models\Profile($this->apiCall('profile-'.$profileId));
  }

  public function createProfile($payload){

  }

  public function updateProfile($profileId, $payload){

  }

  public function getProfileApplications($profileId){

  }
}
?>
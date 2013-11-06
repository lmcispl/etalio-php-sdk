<?php
namespace Etalio;
require_once "etalio_base.php";
require_once "models/profile.php";

/**
 * Extends the EtalioLogin class and adds helper methods for the Etalio Api
 */
abstract class EtalioApi extends EtalioBase
{
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
    $this->domainMap = array_merge($this->domainMap, [
      'myprofile'   => self::BASE_URL . '/' . self::API_VERSION . '/profile/me',
      'profile'   => self::BASE_URL . '/' . self::API_VERSION . '/profile',
      'apps'      => self::BASE_URL . '/' . self::API_VERSION . '/user/applications',
    ]);
  }

  public function isAuthenticated(){
    return ($this->getCurrentProfile())?true:false;
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
      $profile = $this->apiCall('myprofile');
      if($profile) {
        $this->currentProfile = new \Etalio\Models\Profile($profile);
      } else {
        return false;
      }
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
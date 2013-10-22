<?php
require_once "etalio_login.php";

/**
 * Extends the EtalioLogin class and adds helper methods for the Etalio Api
 */
class Etalio extends EtalioLogin
{
  public function __construct($config) {
    parent::__construct($config);
    $this->domainMap = array_merge($this->domainMap, array(
      'apps'      => self::BASE_URL . '/' . self::API_VERSION . '/user/applications',
    ));
  }
}
?>
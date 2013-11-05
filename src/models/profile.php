<?php
namespace Etalio\Models;
require 'etalio_model.php';

class Profile extends EtalioModel
{
  public $id;
  public $name;
  public $msisdn;
  public $verified;

  public function __construct(Array $ob = []) {
    parent::__construct($ob);
  }
  public function parseApiObject(Array $ob = []) {
    if(isset($ob["id"]))$this->id = $ob["id"];
    if(isset($ob["name"]))$this->name = $ob["name"];
    if(isset($ob["msisdn"]))$this->msisdn = $ob["msisdn"];
    if(isset($ob["verified"]))$this->verified = isBoolean($ob["verified"]);
  }
}

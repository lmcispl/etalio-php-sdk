<?php
namespace Etalio\Models;

abstract class EtalioModel
{
  public function __construct($ob = []) {
    if(isset($ob)) $this->parseApiObject($ob);
  }
  abstract public function parseApiObject(Array $ob);
}
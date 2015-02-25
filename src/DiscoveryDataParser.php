<?php

namespace Mdi\Auth\Mc;

/**
 * Class DiscoveryDataParser
 * @package Mdi\Auth
 *
 * Parses the Discovery
 */
class DiscoveryDataParser {

  private $clientId;
  private $clientSecret;
  private $country;
  private $currency;
  private $servingOperator;
  private $subscriberId;

  public function __construct(Array $data) {
    $this->data = $data;
    $this->clientId = $data['client_id'];
    $this->clientSecret = $data['client_secret'];
    $this->country = $data['country'];
    $this->currency = $data['currency'];
    $this->servingOperator = $data['serving_operator'];
    $this->subscriberId = $data['subscriber_id'];
  }

  public function findAuthorizationUrl(){
    return $this->findApi('authorization');
  }

  public function findTokenUri(){
    return $this->findApi('token');
  }

  public function findUserinfoUri(){
    return $this->findApi('userinfo');
  }

  public function findScope(){
    return $this->findApi('scope');
  }

  /**
   * @return mixed
   */
  public function getClientId() {
    return $this->clientId;
  }

  /**
   * @return mixed
   */
  public function getClientSecret() {
    return $this->clientSecret;
  }

  /**
   * @return mixed
   */
  public function getCountry() {
    return $this->country;
  }

  /**
   * @return mixed
   */
  public function getCurrency() {
    return $this->currency;
  }

  /**
   * @return mixed
   */
  public function getServingOperator() {
    return $this->servingOperator;
  }

  /**
   * @return mixed
   */
  public function getSubscriberId() {
    return $this->subscriberId;
  }

  /**
   * @param string $apiName
   * @return mixed
   */
  private function findApi($apiName) {
    if (!array_key_exists('apis', $this->data))
      return null;
    $apis = $this->data['apis'];
    if (!array_key_exists('operatorid', $apis))
      return null;
    $operatorid = $apis['operatorid'];
    if (!array_key_exists('link', $operatorid))
      return null;
    $links = $operatorid['link'];
    foreach ($links as $api) {
      if ($api['rel'] === $apiName)
        return $api['href'];
    }
    return null;
  }
}

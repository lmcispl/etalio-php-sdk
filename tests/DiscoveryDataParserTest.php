<?php

use Mdi\Auth\Mc\DiscoveryDataParser;

class DiscoveryDataParserTest extends PHPUnit_Framework_TestCase {

  private function getBaseData(){
    $clientId = 'some-id';
    $clientSecret = 'secret';
    $country = 'se';
    $currency = 'sek';
    $servingOperator = 'operator';
    $subscriberId = null;
    $data = [
      'client_id' => $clientId,
      'client_secret' => $clientSecret,
      'country' => $country,
      'currency' => $currency,
      'serving_operator' => $servingOperator,
      'subscriber_id' => $subscriberId
    ];
    return $data;
  }

  public function testParsingStandardAttributes() {
    $clientId = 'some-id';
    $clientSecret = 'secret';
    $country = 'se';
    $currency = 'sek';
    $servingOperator = 'operator';
    $subscriberId = null;
    $data = [
      'client_id' => $clientId,
      'client_secret' => $clientSecret,
      'country' => $country,
      'currency' => $currency,
      'serving_operator' => $servingOperator,
      'subscriber_id' => $subscriberId
    ];
    $p = new DiscoveryDataParser($data);

    $this->assertEquals($clientId, $p->getClientId());
    $this->assertEquals($clientSecret, $p->getClientSecret());
    $this->assertEquals($country, $p->getCountry());
    $this->assertEquals($currency, $p->getCurrency());
    $this->assertEquals($servingOperator, $p->getServingOperator());
    $this->assertEquals($subscriberId, $p->getSubscriberId());
  }

  public function testGetApis() {
    $d = $this->getBaseData();
    $host = 'https://exemple.com/auth';
    $d = array_merge($d, [
      'apis' => [
        'operatorid' => [
          'link' => [
            [
              'rel' => 'authorization',
              'href' => $host
            ]
          ]
        ]
      ]
    ]);
    $p = new DiscoveryDataParser($d);
    $this->assertEquals($host, $p->findAuthorizationUrl());
    $this->assertNull($p->findTokenUri());
    $this->assertNull($p->findUserinfoUri());
    $this->assertNull($p->findScope());
  }

  public function testTokenUri() {
    $d = $this->getBaseData();
    $host = 'https://exemple.com/auth';
    $d = array_merge($d, [
      'apis' => [
        'operatorid' => [
          'link' => [
            [
              'rel' => 'token',
              'href' => $host
            ]
          ]
        ]
      ]
    ]);
    $p = new DiscoveryDataParser($d);
    $this->assertEquals($host, $p->findTokenUri());
    $this->assertNull($p->findAuthorizationUrl());
    $this->assertNull($p->findUserinfoUri());
    $this->assertNull($p->findScope());
  }

  public function testUserinfo() {
    $d = $this->getBaseData();
    $host = 'https://exemple.com/auth';
    $d = array_merge($d, [
      'apis' => [
        'operatorid' => [
          'link' => [
            [
              'rel' => 'userinfo',
              'href' => $host
            ]
          ]
        ]
      ]
    ]);
    $p = new DiscoveryDataParser($d);
    $this->assertEquals($host, $p->findUserinfoUri());
    $this->assertNull($p->findTokenUri());
    $this->assertNull($p->findAuthorizationUrl());
    $this->assertNull($p->findScope());
  }

  public function testNoApis() {
    $d = $this->getBaseData();
    $host = 'https://exemple.com/auth';
    $d = array_merge($d, [ ]);
    $p = new DiscoveryDataParser($d);
    $this->assertNull($p->findUserinfoUri());
    $this->assertNull($p->findTokenUri());
    $this->assertNull($p->findAuthorizationUrl());
    $this->assertNull($p->findScope());
  }


}

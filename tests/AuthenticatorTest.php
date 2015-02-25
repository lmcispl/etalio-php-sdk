<?php
namespace Mdi\Auth\Mc;

class AuthenticatorTest extends \PHPUnit_Framework_TestCase {
  private function getDefaultDiscoverData(){
    $d = $this->getMockBuilder('Mdi\Auth\Mc\DiscoveryDataParser')
      ->disableOriginalConstructor()
      ->setMethods(['findAuthorizationUrl',
        'findUserinfoUri',
        'findTokenUri',
        'getClientId',
        'getClientSecret',
        'findScope',
        'getCountry',
        'getCurrency',
        'getSubscriberId',
      ])
      ->getMock();
    $domain = 'https://exemple.com/auth';
    $d->expects($this->once())
      ->method('findAuthorizationUrl')
      ->will($this->returnValue($domain));
    $token = 'https://exemple.com/token';
    $d->expects($this->once())
      ->method('findTokenUri')
      ->will($this->returnValue($token));

    $d->expects($this->any())
      ->method('getClientId')
      ->will($this->returnValue('client_ids'));

    $d->expects($this->any())
      ->method('getClientSecret')
      ->will($this->returnValue('client_secrets'));

    return $d;
  }

  public function testIsMdiIfMdiIssuerOfToken() {
    $m = $this->getMockBuilder('Mdi\Auth\Mc\Authenticator')
              ->setMethods(null)
              ->getMock();

    $d = $this->getMockBuilder('Mdi\Auth\Mc\DiscoveryDataParser')
              ->disableOriginalConstructor()
              ->setMethods(['findAuthorizationUrl',
                            'findUserinfoUri',
                            'findTokenUri',
                            'getClientId',
                            'findScope',
                            'getClientSecret',
                            'getCountry',
                            'getCurrency',
                            'getSubscriberId',
              ])
              ->getMock();
    $domain = 'https://exemple.com/auth';
    $d->expects($this->once())
      ->method('findAuthorizationUrl')
      ->will($this->returnValue($domain));
    $token = 'https://exemple.com/token';
    $d->expects($this->once())
      ->method('findTokenUri')
      ->will($this->returnValue($token));

    $m->loadDiscovery($d);
    $this->assertTrue($m->isDiscoveryLoaded());
    $this->assertStringStartsWith($domain, $m->getLoginUrl([]));
  }

  public function testIdTokenParsing() {
    $m = $this->getMockBuilder('Mdi\Auth\Mc\Authenticator')
      ->setMethods([
        'makeRequest',
        'getCodeFromRequest',
      ])
      ->getMock();


    $m->loadDiscovery($this->getDefaultDiscoverData());
//    print_r($m);
    $m->expects($this->once())
      ->method('getCodeFromRequest')
      ->will($this->returnValue('CODE'));

    $access_token = "deed8f9306a1fb235e6c035c906a15d51bdcc5db";
    $m->expects($this->once())
      ->method('makeRequest')
      ->will($this->returnValue('{
        "access_token" : "'.$access_token.'",
        "expires_in" : 3600,
        "token_type" : "bearer",
        "scope" : "openid profile email",
        "id_token" : "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiIsImtpZCI6IjkzOTAwYzUxYzE4MDJlNTZmM2NiZjIzMjcxNWNkYzY5In0.eyJpc3MiOiJodHRwczovL2FwaS1ldGFsaW8uM2ZzLnNpIiwic3ViIjoiMGQ5MDkzM2QtYzQ0YS00MmExLTkxNWUtYzk4YThhZmEzMWI2IiwiYXVkIjoiZmY0ZmQyYmJmZWU4YjNmNzRjYmFjNDMyMDJjMzQ0ZTEiLCJpYXQiOjE0MjMxMjQzNjMsImV4cCI6MTQyMzEyNzk2MywiYXV0aF90aW1lIjoxNDIzMTI0MzYzLCJub25jZSI6IjQ1YjBmOGYwMWFmMTQ5YzMzMWVlOWY0Zjc4MmY3MDZiIn0.zI3ugIJ4rtOnnlooXd358hgF6lNHFxGzjKdS6Y9dITdNN9Kv5X7iAnq2qlM8aADaiiagq-ldbLF39xA0KycY7bkP5TMS0JYEnynsh8SrmI_r5eiaZsDvGrALAGBDFbjLj_zfDx-X-JsR66aiyvj_z_VZCxufBrMl935eGQB5wik"
      }'));
    $this->assertEquals($access_token, $m->authenticateUser('CODE'));

  }

}

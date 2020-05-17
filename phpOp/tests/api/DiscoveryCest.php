<?php

class DiscoveryCest
{
    public function _before(ApiTester $I)
    {
    }

    // tests
    public function openidConfigurationTest(ApiTester $I)
    {
        $I->sendGET('/.well-known/openid-configuration');
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseMatchesJsonType([
            'authorization_endpoint' => 'string:url',
            'issuer' => 'string'
        ]);
    }

    public function webfingerTest(ApiTester $I)
    {
        $url = $I->getCurrentUrl();
        $I->sendGET(
            '/.well-known/webfinger',
            [
                'resource' => $url,
                'rel' => 'http://openid.net/specs/connect/1.0/issuer'
            ]
        );
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseJsonMatchesXpath('//subject');
        $I->seeResponseJsonMatchesXpath('//links');
    }
}

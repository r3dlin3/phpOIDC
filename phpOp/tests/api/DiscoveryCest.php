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
            'token_endpoint' => 'string:url',
            'userinfo_endpoint' => 'string:url',
            'check_session_iframe' => 'string:url',
            'end_session_endpoint' => 'string:url',
            'jwks_uri' => 'string:url',
            'issuer' => 'string'
        ]);

        list($jwk_url) = $I->grabDataFromResponseByJsonPath('$.jwks_uri');
        $I->sendGET($jwk_url);
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseMatchesJsonType([
            'keys' => 'array',
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

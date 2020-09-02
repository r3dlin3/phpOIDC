<?php
use \Codeception\Step\Argument\PasswordArgument;

class UserCest
{
    public function _before(ApiTester $I)
    {
    }

    // tests
    public function getAllTest(ApiTester $I)
    {
        $access_token = $I->getAccessToken();
        $I->assertNotNull($access_token);
        $I->amBearerAuthenticated($access_token);
        $I->sendGET('/admin/api/index.php/users');
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseMatchesJsonType([
            'total_rows' => 'integer',
            'from' => 'integer',
            'to' => 'integer',
            'results' => 'array'
        ]);
    }

    public function getAllOptionsTest(ApiTester $I)
    {
        $I->sendOPTIONS('/admin/api/index.php/users');
        $I->seeResponseCodeIs(200);
        $I->seeHttpHeader('Access-Control-Allow-Origin');
    }

    public function getPaginatedResult(ApiTester $I)
    {
        $access_token = $I->getAccessToken();
        $I->assertNotNull($access_token);
        $I->amBearerAuthenticated($access_token);
        $I->sendGET('/admin/api/index.php/users', ['limit' => 1, 'offset' => 0]);
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseMatchesJsonType([
            'total_rows' => 'integer',
            'from' => 'integer',
            'to' => 'integer',
            'results' => 'array'
        ]);
        $I->seeResponseContainsJson([
            'from' => '1',
            'to' => '1',
        ]);
    }

    public function getUserOptionsTest(ApiTester $I)
    {
        $I->sendOPTIONS('/admin/api/index.php/users/1');
        $I->seeResponseCodeIs(200);
        $I->seeHttpHeader('Access-Control-Allow-Origin');
    }
}

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

    public function getUserTest(ApiTester $I)
    {
        $access_token = $I->getAccessToken();
        $I->assertNotNull($access_token);
        $I->amBearerAuthenticated($access_token);
        $I->sendGET('/admin/api/index.php/users/1');
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseMatchesJsonType([
            'id' => 'integer',
            'login' => 'string',
            'enabled' => 'boolean',
        ]);
    }

    public function e2eTest(ApiTester $I)
    {
        $access_token = $I->getAccessToken();
        $I->assertNotNull($access_token);
        $I->amBearerAuthenticated($access_token);

        // Create User
        $login = uniqid();
        $password = uniqid();
        $user = [
            "login" => $login,
            "enabled" => true,
            "password" => $password
        ];
        $I->sendPOST('/admin/api/index.php/users', json_encode($user));
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        list($id) = $I->grabDataFromResponseByJsonPath('$.id');

        // Check user is present
        $I->sendGET('/admin/api/index.php/users/' . $id);
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseMatchesJsonType([
            'id' => 'integer',
            'login' => 'string',
            'enabled' => 'boolean',
        ]);

        // Validate login & password
        $access_token2 = $I->getAccessToken($login, $password);;
        $I->assertNotNull($access_token2);

        // Delete user
        $I->sendDELETE('/admin/api/index.php/users/' . $id);
        $I->seeResponseCodeIs(204);
    }

    public function updateTest(ApiTester $I)
    {
        $access_token = $I->getAccessToken();
        $I->assertNotNull($access_token);
        $I->amBearerAuthenticated($access_token);

        $login = uniqid();

        // Create User
        $user = [
            "login" => $login,
            "enabled" => true,
            "password" => uniqid()
        ];
        $I->sendPOST('/admin/api/index.php/users', json_encode($user));
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        list($id) = $I->grabDataFromResponseByJsonPath('$.id');
        
        $password = uniqid();
        $user = [
            "id" => $id,
            "email_verified" => true,
            "middle_name"=> "middle",
            "password" => $password
        ];
        // Update user is present
        $I->sendPATCH('/admin/api/index.php/users/' . $id, json_encode($user));
        $I->seeResponseCodeIs(200);
        $I->seeResponseIsJson();
        $I->seeResponseMatchesJsonType([
            'id' => 'integer',
            'login' => 'string',
            'enabled' => 'boolean',
        ]);

        // Validate login & password
        $access_token2 = $I->getAccessToken($login, $password);;
        $I->assertNotNull($access_token2);

        // Delete user
        $I->sendDELETE('/admin/api/index.php/users/' . $id);
        $I->seeResponseCodeIs(204);
    }
}

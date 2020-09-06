<?php

use Codeception\Step\Argument\PasswordArgument;

/**
 * Inherited Methods
 * @method void wantToTest($text)
 * @method void wantTo($text)
 * @method void execute($callable)
 * @method void expectTo($prediction)
 * @method void expect($prediction)
 * @method void amGoingTo($argumentation)
 * @method void am($role)
 * @method void lookForwardTo($achieveValue)
 * @method void comment($description)
 * @method void pause()
 *
 * @SuppressWarnings(PHPMD)
 */
class ApiTester extends \Codeception\Actor
{
    use _generated\ApiTesterActions;

    public function getAccessToken(
        $username = 'a.b@gmail.com',
        $password = 'FooBarFooBar'
    ) {
        $client_id = 'vuejsclient';
        $redirect_uri = 'http://localhost:8080/callback.html';

        $I = $this;
        $I->amOnPage("index.php/auth?client_id=$client_id&redirect_uri=$redirect_uri&response_type=id_token%20token&scope=openid%20profile&state=b89d55310cc94592863db682694d1973&nonce=e88cf27bd8a940e8924051bcc973b6ee");
        // Login Page
        $I->seeElement('input', ['name' => 'username']);
        $I->seeElement('input', ['name' => 'password']);
        $I->fillField(['name' => 'username'], $username);
        $I->fillField(['name' => 'password'], new PasswordArgument($password));
        $I->followRedirects(false);
        $I->click('#login');
        $url = $I->grabHttpHeader('Location');
        // codecept_debug($url);
        $access_token = $I->grabFragmentParameter($url, 'access_token');
        // codecept_debug($access_token);
        return $access_token;
    }
}

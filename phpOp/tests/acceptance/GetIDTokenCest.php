<?php
use \Codeception\Step\Argument\PasswordArgument;

class GetIDTokenCest
{
    public function _before(AcceptanceTester $I)
    {
    }

    // tests
    public function authenticate(AcceptanceTester $I)
    {
        $I->amOnPage('/');
        $I->selectOption('provider', 'http://phpoidc:8080/phpOp');
        $I->selectOption('response_type', 'code');
        $I->checkOption('scope_openid');
        $I->checkOption('scope_profile');
        $I->click('Connect');
        
        // Login Page
        $I->seeElement('input', ['name' => 'username']);
        $I->seeElement('input', ['name' => 'password']);
        $I->fillField(['name' => 'username'], 'alice');
        $I->fillField(['name' => 'password'], new PasswordArgument('wonderland'));
        $I->click('#login');
        
        // Consent Page
        // $I->makeHtmlSnapshot('consent');
        $I->dontSeeElement('.alert');
        $I->selectOption('trust', 'once');
        $I->click('#confirmed');
        
        // RP page with token info
        $I->see('UserInfo Response');
        $I->makeHtmlSnapshot('userinfo');
        $I->see('alice@wonderland.com');
        $I->see('ID_Token Response');
    }

    private function generateRandomString($length = 10) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    } 
    public function register(AcceptanceTester $I)
    {
        $I->amOnPage('/');
        $I->selectOption('provider', 'http://phpoidc:8080/phpOp');
        $I->selectOption('response_type', 'code token');
        $I->checkOption('scope_openid');
        $I->checkOption('scope_profile');
        $I->click('Connect');
        
        // Login Page
        $I->click('#register');
        
        // Register
        $email = $this->generateRandomString() . '@example.com';
        $password = $this->generateRandomString() . '@example.com';
        $I->seeElement('input', ['name' => 'given_name']);
        $I->seeElement('input', ['name' => 'family_name']);
        $I->fillField(['name' => 'email'], $email);
        $I->fillField(['name' => 'given_name'], 'aa');
        $I->fillField(['name' => 'family_name'], 'aa');
        $I->fillField(['name' => 'password'], new PasswordArgument($password));
        $I->click('#register');
        
        // Register success
        $I->dontSeeElement('.invalid-feedback');
        $I->click('#register_continue');
        
        // Login

        $I->seeElement('input', ['name' => 'password']);
        $I->fillField(['name' => 'password'], new PasswordArgument($password));
        $I->click('#login');

        // Consent Page
        // $I->makeHtmlSnapshot('consent');
        $I->dontSeeElement('.alert');
        $I->seeElement('//input[@name="trust"]');


    }
}

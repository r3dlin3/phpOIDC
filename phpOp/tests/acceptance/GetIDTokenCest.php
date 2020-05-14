<?php
use \Codeception\Step\Argument\PasswordArgument;

class GetIDTokenCest
{
    public function _before(AcceptanceTester $I)
    {
    }

    // tests
    public function tryToTest(AcceptanceTester $I)
    {
        $I->amOnPage('/');
        $I->selectOption('provider', 'http://phpoidc:8080/phpOp');
        $I->selectOption('response_type', 'code token');
        $I->checkOption('scope_openid');
        $I->checkOption('scope_profile');
        $I->click('Connect');
        
        // Login Page
        $I->seeElement('input', ['name' => 'username']);
        $I->seeElement('input', ['name' => 'password']);
        $I->click('//form/*[@type="submit"]');
        // Consent Page
        $I->checkOption('agreed');
        $I->selectOption('trust', 'once');
        $I->click('confirm');
        
        // RP page with token info
        $I->see('UserInfo Response');
        $I->see('ID_Token Response');

        





        // $I->fillField('password', new PasswordArgument('thisissecret'));
    }
}

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
        $I->fillField(['name' => 'username'], 'alice');
        $I->fillField(['name' => 'password'], new PasswordArgument('wonderland'));
        $I->click('#login');
        
        // Consent Page
        // $I->makeHtmlSnapshot('consent');
        $I->dontSeeElement('.alert');
        $I->selectOption('trust', 'once');
        $I->click('confirm');
        
        // RP page with token info
        $I->see('UserInfo Response');
        $I->see('ID_Token Response');

        





        // $I->fillField('password', new PasswordArgument('thisissecret'));
    }
}

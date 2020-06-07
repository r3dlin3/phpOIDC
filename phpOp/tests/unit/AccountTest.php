<?php 
class AccountTest extends \Codeception\Test\Unit
{
    /**
     * @var \UnitTester
     */
    protected $tester;
    
    protected function _before()
    {
    }

    protected function _after()
    {
    }

    // tests
    public function testIterator()
    {
        $login = uniqid();
        $a = new Account();
        $a->setLogin($login);
        $found = false;
        foreach($a as $key=>$val) {
            if ($key === 'login') {
                $found = true;
                $this->assertEquals($login, $val);
            }

        }
        $this->assertTrue($found);
    }
}
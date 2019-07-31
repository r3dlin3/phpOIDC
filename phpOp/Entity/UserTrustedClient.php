<?php
require_once "BaseEntity.php";

use Doctrine\ORM\Mapping as ORM;


class UserTrustedClient extends BaseEntity
{

    private $id;

    private $account_id;

    private $client_id;


    private $Account;
    private $Client;

}
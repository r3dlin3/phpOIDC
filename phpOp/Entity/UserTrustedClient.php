<?php
require_once "BaseEntity.php";

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\HasLifecycleCallbacks
 */
class UserTrustedClient extends BaseEntity
{

    private $id;

    private $account_id;

    private $client_id;


    private $Account;
    private $Client;
    
    public function jsonSerialize() : array
    {
        $json = array();
        $vars1 = get_object_vars($this);
        foreach ($vars1 as $key => $value) {
            if(!($value instanceof Doctrine\ORM\PersistentCollection) && !($value instanceof BaseEntity)) {
                $json[$key] = $value;

            }
        }

        return $json;
    }
}
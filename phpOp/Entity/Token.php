<?php
require_once "BaseEntity.php";


use Doctrine\ORM\Mapping as ORM;



/**
 * @ORM\Entity
 * @ORM\Table(name="token", indexes={@ORM\Index(name="account_id_idx", columns={"account_id"})})
 **/
class Token extends BaseEntity implements JsonSerializable, ArrayAccess
{
    /** @ORM\Id
     *  @ORM\Column(type="integer")
     *  @ORM\GeneratedValue
     **/
    private $id;

    /** @ORM\Column(type="integer") **/
    private $account_id;

    /** @ORM\Column(type="text") **/
    private $token;

    /** @ORM\Column(type="smallint") **/
    private $token_type;

    /** @ORM\Column(type="string", length=255) **/
    private $client;

    /** @ORM\Column(type="text") **/
    private $details;

    /** @ORM\Column(type="datetime") **/
    private $issued_at;

    /** @ORM\Column(type="datetime") **/
    private $expiration_at;

    /** @ORM\Column(type="text") **/
    private $info;

    /**
     * @ORM\ManyToOne(targetEntity="Account", inversedBy="tokens")
     * @ORM\JoinColumn(name="account_id", referencedColumnName="id")
     */
    private $account;


    private static $tableFields = array(
        'id',
        'account_id',
        'token',
        'token_type',
        'client',
        'details',
        'issued_at',
        'expiration_at',
        'info'
    );


    public function offsetExists($offset)
    {
        return in_array($offset, self::$tableFields);
    }

    public function offsetSet($offset, $value)
    {
        $method = $this->getSetterName(self::$tableFields, $offset);
        if($method)
            $this->{$method}($value);
    }

    public function offsetGet($offset)
    {
        $method = $this->getGetterName(self::$tableFields, $offset);
        if($method)
            return $this->{$method}();
        else
            return null;
    }

    public function offsetUnset($offset)
    {
    }


    /**
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return mixed
     */
    public function getAccountId()
    {
        return $this->account_id;
    }

    /**
     * @param mixed $account_id
     */
    public function setAccountId($account_id)
    {
        $this->account_id = $account_id;
    }

    /**
     * @return mixed
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @param mixed $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * @return mixed
     */
    public function getTokenType()
    {
        return $this->token_type;
    }

    /**
     * @param mixed $token_type
     */
    public function setTokenType($token_type)
    {
        $this->token_type = $token_type;
    }

    /**
     * @return mixed
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * @param mixed $client
     */
    public function setClient($client)
    {
        $this->client = $client;
    }

    /**
     * @return mixed
     */
    public function getDetails()
    {
        return $this->details;
    }

    /**
     * @param mixed $details
     */
    public function setDetails($details)
    {
        $this->details = $details;
    }

    /**
     * @return mixed
     */
    public function getIssuedAt()
    {
        return $this->issued_at;
    }

    /**
     * @param mixed $issued_at
     */
    public function setIssuedAt($issued_at)
    {
        $this->issued_at = $issued_at;
    }

    /**
     * @return mixed
     */
    public function getExpirationAt()
    {
        return $this->expiration_at;
    }

    /**
     * @param mixed $expiration_at
     */
    public function setExpirationAt($expiration_at)
    {
        $this->expiration_at = $expiration_at;
    }

    /**
     * @return mixed
     */
    public function getInfo()
    {
        return $this->info;
    }

    /**
     * @param mixed $info
     */
    public function setInfo($info)
    {
        $this->info = $info;
    }

    /**
     * @return mixed
     */
    public function getAccount()
    {
        return $this->account;
    }

    /**
     * @param mixed $account
     */
    public function setAccount($account)
    {
        $this->account = $account;
    }


    public function jsonSerialize()
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
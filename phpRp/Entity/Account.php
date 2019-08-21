<?php
require_once "BaseEntity.php";


use Doctrine\ORM\Mapping as ORM;


/**
 * @ORM\Entity
 * @ORM\Table(name="account")
 **/
Class Account extends BaseEntity implements JsonSerializable, ArrayAccess {

    /** @ORM\Id
     *  @ORM\Column(type="integer")
     *  @ORM\GeneratedValue
     **/
    private $id;

    /**
     * @ORM\Column(type="string",length=255, unique=true)
     */
    private $login;

    /** @ORM\Column(type="boolean", nullable=true, options={"default":true}) **/
    private $enabled;

    /** @ORM\Column(type="string",length=255) **/
    private $crypted_password;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $name;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $name_ja_kana_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $name_ja_hani_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $given_name;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $given_name_ja_kana_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $given_name_ja_hani_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $family_name;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $family_name_ja_kana_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $family_name_ja_hani_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $middle_name;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $middle_name_ja_kana_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $middle_name_ja_hani_jp;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $nickname;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $preferred_username;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $profile;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $picture;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $website;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $email;

    /** @ORM\Column(type="boolean", nullable=true, options={"default":false}) **/
    private $email_verified;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $gender;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $birthdate;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $zoneinfo;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $locale;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $phone_number;

    /** @ORM\Column(type="boolean", nullable=true, options={"default":false}) **/
    private $phone_number_verified;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $address;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $updated_at;


    /**
     * @ORM\OneToMany(targetEntity="Token", mappedBy="account")
     */
    private $tokens;

    /**
     * @ORM\ManyToMany(targetEntity="Client", inversedBy="accounts")
     * @ORM\JoinTable(name="user_trusted_client",
     *      joinColumns={@ORM\JoinColumn(name="account_id", referencedColumnName="id")},
     *      inverseJoinColumns={@ORM\JoinColumn(name="client_id", referencedColumnName="id")}
     *      )
     */
    private $trustedclients;

    private static $tableFields = array(
        'id',
        'enabled',
        'login',
        'crypted_password',
        'name',
        'name_ja_kana_jp',
        'name_ja_hani_jp',
        'given_name',
        'given_name_ja_kana_jp',
        'given_name_ja_hani_jp',
        'family_name',
        'family_name_ja_kana_jp',
        'family_name_ja_hani_jp',
        'middle_name',
        'middle_name_ja_kana_jp',
        'middle_name_ja_hani_jp',
        'nickname',
        'preferred_username',
        'profile',
        'picture',
        'website',
        'email',
        'email_verified',
        'gender',
        'birthdate',
        'zoneinfo',
        'locale',
        'phone_number',
        'phone_number_verified',
        'address',
        'updated_at'
    );

    /**
     * Creates a Doctrine Collection for members.
     */
    public function __construct()
    {
        $this->tokens = new \Doctrine\Common\Collections\ArrayCollection();
        $this->trustedclients = new \Doctrine\Common\Collections\ArrayCollection();
    }


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
    public function getEnabled()
    {
        return $this->enabled;
    }

    /**
     * @param mixed $enabled
     */
    public function setEnabled($enabled)
    {
        $this->enabled = $enabled;
    }

    /**
     * @return mixed
     */
    public function getLogin()
    {
        return $this->login;
    }

    /**
     * @param mixed $login
     */
    public function setLogin($login)
    {
        $this->login = $login;
    }

    /**
     * @return mixed
     */
    public function getCryptedPassword()
    {
        return $this->crypted_password;
    }

    /**
     * @param mixed $crypted_password
     */
    public function setCryptedPassword($crypted_password)
    {
        $this->crypted_password = $crypted_password;
    }

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @param mixed $name
     */
    public function setName($name)
    {
        $this->name = $name;
    }

    /**
     * @return mixed
     */
    public function getNameJaKanaJp()
    {
        return $this->name_ja_kana_jp;
    }

    /**
     * @param mixed $name_ja_kana_jp
     */
    public function setNameJaKanaJp($name_ja_kana_jp)
    {
        $this->name_ja_kana_jp = $name_ja_kana_jp;
    }

    /**
     * @return mixed
     */
    public function getNameJaHaniJp()
    {
        return $this->name_ja_hani_jp;
    }

    /**
     * @param mixed $name_ja_hani_jp
     */
    public function setNameJaHaniJp($name_ja_hani_jp)
    {
        $this->name_ja_hani_jp = $name_ja_hani_jp;
    }

    /**
     * @return mixed
     */
    public function getGivenName()
    {
        return $this->given_name;
    }

    /**
     * @param mixed $given_name
     */
    public function setGivenName($given_name)
    {
        $this->given_name = $given_name;
    }

    /**
     * @return mixed
     */
    public function getGivenNameJaKanaJp()
    {
        return $this->given_name_ja_kana_jp;
    }

    /**
     * @param mixed $given_name_ja_kana_jp
     */
    public function setGivenNameJaKanaJp($given_name_ja_kana_jp)
    {
        $this->given_name_ja_kana_jp = $given_name_ja_kana_jp;
    }

    /**
     * @return mixed
     */
    public function getGivenNameJaHaniJp()
    {
        return $this->given_name_ja_hani_jp;
    }

    /**
     * @param mixed $given_name_ja_hani_jp
     */
    public function setGivenNameJaHaniJp($given_name_ja_hani_jp)
    {
        $this->given_name_ja_hani_jp = $given_name_ja_hani_jp;
    }

    /**
     * @return mixed
     */
    public function getFamilyName()
    {
        return $this->family_name;
    }

    /**
     * @param mixed $family_name
     */
    public function setFamilyName($family_name)
    {
        $this->family_name = $family_name;
    }

    /**
     * @return mixed
     */
    public function getFamilyNameJaKanaJp()
    {
        return $this->family_name_ja_kana_jp;
    }

    /**
     * @param mixed $family_name_ja_kana_jp
     */
    public function setFamilyNameJaKanaJp($family_name_ja_kana_jp)
    {
        $this->family_name_ja_kana_jp = $family_name_ja_kana_jp;
    }

    /**
     * @return mixed
     */
    public function getFamilyNameJaHaniJp()
    {
        return $this->family_name_ja_hani_jp;
    }

    /**
     * @param mixed $family_name_ja_hani_jp
     */
    public function setFamilyNameJaHaniJp($family_name_ja_hani_jp)
    {
        $this->family_name_ja_hani_jp = $family_name_ja_hani_jp;
    }

    /**
     * @return mixed
     */
    public function getMiddleName()
    {
        return $this->middle_name;
    }

    /**
     * @param mixed $middle_name
     */
    public function setMiddleName($middle_name)
    {
        $this->middle_name = $middle_name;
    }

    /**
     * @return mixed
     */
    public function getMiddleNameJaKanaJp()
    {
        return $this->middle_name_ja_kana_jp;
    }

    /**
     * @param mixed $middle_name_ja_kana_jp
     */
    public function setMiddleNameJaKanaJp($middle_name_ja_kana_jp)
    {
        $this->middle_name_ja_kana_jp = $middle_name_ja_kana_jp;
    }

    /**
     * @return mixed
     */
    public function getMiddleNameJaHaniJp()
    {
        return $this->middle_name_ja_hani_jp;
    }

    /**
     * @param mixed $middle_name_ja_hani_jp
     */
    public function setMiddleNameJaHaniJp($middle_name_ja_hani_jp)
    {
        $this->middle_name_ja_hani_jp = $middle_name_ja_hani_jp;
    }

    /**
     * @return mixed
     */
    public function getNickname()
    {
        return $this->nickname;
    }

    /**
     * @param mixed $nickname
     */
    public function setNickname($nickname)
    {
        $this->nickname = $nickname;
    }

    /**
     * @return mixed
     */
    public function getPreferredUsername()
    {
        return $this->preferred_username;
    }

    /**
     * @param mixed $preferred_username
     */
    public function setPreferredUsername($preferred_username)
    {
        $this->preferred_username = $preferred_username;
    }

    /**
     * @return mixed
     */
    public function getProfile()
    {
        return $this->profile;
    }

    /**
     * @param mixed $profile
     */
    public function setProfile($profile)
    {
        $this->profile = $profile;
    }

    /**
     * @return mixed
     */
    public function getPicture()
    {
        return $this->picture;
    }

    /**
     * @param mixed $picture
     */
    public function setPicture($picture)
    {
        $this->picture = $picture;
    }

    /**
     * @return mixed
     */
    public function getWebsite()
    {
        return $this->website;
    }

    /**
     * @param mixed $website
     */
    public function setWebsite($website)
    {
        $this->website = $website;
    }

    /**
     * @return mixed
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @param mixed $email
     */
    public function setEmail($email)
    {
        $this->email = $email;
    }

    /**
     * @return mixed
     */
    public function getEmailVerified()
    {
        return $this->email_verified;
    }

    /**
     * @param mixed $email_verified
     */
    public function setEmailVerified($email_verified)
    {
        $this->email_verified = $email_verified;
    }

    /**
     * @return mixed
     */
    public function getGender()
    {
        return $this->gender;
    }

    /**
     * @param mixed $gender
     */
    public function setGender($gender)
    {
        $this->gender = $gender;
    }

    /**
     * @return mixed
     */
    public function getBirthdate()
    {
        return $this->birthdate;
    }

    /**
     * @param mixed $birthdate
     */
    public function setBirthdate($birthdate)
    {
        $this->birthdate = $birthdate;
    }

    /**
     * @return mixed
     */
    public function getZoneinfo()
    {
        return $this->zoneinfo;
    }

    /**
     * @param mixed $zoneinfo
     */
    public function setZoneinfo($zoneinfo)
    {
        $this->zoneinfo = $zoneinfo;
    }

    /**
     * @return mixed
     */
    public function getLocale()
    {
        return $this->locale;
    }

    /**
     * @param mixed $locale
     */
    public function setLocale($locale)
    {
        $this->locale = $locale;
    }

    /**
     * @return mixed
     */
    public function getPhoneNumber()
    {
        return $this->phone_number;
    }

    /**
     * @param mixed $phone_number
     */
    public function setPhoneNumber($phone_number)
    {
        $this->phone_number = $phone_number;
    }

    /**
     * @return mixed
     */
    public function getPhoneNumberVerified()
    {
        return $this->phone_number_verified;
    }

    /**
     * @param mixed $phone_number_verified
     */
    public function setPhoneNumberVerified($phone_number_verified)
    {
        $this->phone_number_verified = $phone_number_verified;
    }

    /**
     * @return mixed
     */
    public function getAddress()
    {
        return $this->address;
    }

    /**
     * @param mixed $address
     */
    public function setAddress($address)
    {
        $this->address = $address;
    }

    /**
     * @return mixed
     */
    public function getUpdatedAt()
    {
        return $this->updated_at;
    }

    /**
     * @param mixed $updated_at
     */
    public function setUpdatedAt($updated_at)
    {
        $this->updated_at = $updated_at;
    }

    /**
     * @return mixed
     */
    public function getTokens()
    {
        return $this->tokens;
    }

    /**
     * @param mixed $Tokens
     */
    public function setTokens($Tokens)
    {
        $this->tokens = $Tokens;
    }

    /**
     * @return mixed
     */
    public function getTrustedClients()
    {
        return $this->trustedclients;
    }

    /**
     * @param mixed $TrustedClients
     */
    public function setTrustedClients($TrustedClients)
    {
        $this->trustedclients = $TrustedClients;
    }

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

    public function addToken($token)
    {
        $token->setAccount($this);
        $this->tokens[] = $token;
    }

    public function addTrustedClient($client)
    {
        $client->addAccount($this);
        $this->trustedclients[] = $client;
    }

}
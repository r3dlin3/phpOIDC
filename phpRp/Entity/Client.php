<?php
require_once "BaseEntity.php";


use Doctrine\ORM\Mapping as ORM;


/**
 * @ORM\Entity
 * @ORM\Table(name="client")
 **/
class Client extends BaseEntity implements JsonSerializable, ArrayAccess
{
    /** @ORM\Id
     *  @ORM\Column(type="integer")
     *  @ORM\GeneratedValue
     **/
    private $id;

    /** @ORM\Column(type="integer") **/
    private $client_id_issued_at;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $client_id;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $client_secret;

    /** @ORM\Column(type="integer", nullable=true) **/
    private $client_secret_expires_at;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $registration_access_token;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $registration_client_uri_path;

    /** @ORM\Column(type="text", nullable=true) **/
    private $contacts;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $application_type;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $client_name;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $logo_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $tos_uri;

    /** @ORM\Column(type="text", nullable=true) **/
    private $redirect_uris;

    /** @ORM\Column(type="text", nullable=true) **/
    private $post_logout_redirect_uris;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $token_endpoint_auth_method;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $token_endpoint_auth_signing_alg;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $policy_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $jwks_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $jwk_encryption_uri;

    /** @ORM\Column(type="text", nullable=true) **/
    private $jwks;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $x509_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $x509_encryption_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $sector_identifier_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $subject_type;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $request_object_signing_alg;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $userinfo_signed_response_alg;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $userinfo_encrypted_response_alg;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $userinfo_encrypted_response_enc;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $id_token_signed_response_alg;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $id_token_encrypted_response_alg;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $id_token_encrypted_response_enc;

    /** @ORM\Column(type="integer", nullable=true) **/
    private $default_max_age;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $require_auth_time;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $default_acr_values;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $initiate_login_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $post_logout_redirect_uri;

    /** @ORM\Column(type="text", nullable=true) **/
    private $request_uris;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $grant_types;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $response_types;

    /**
     * @ORM\ManyToMany(targetEntity="Account", mappedBy="trustedclients")
     */
    private $accounts;

    private static $tableFields = array(
        'id',
        'client_id_issued_at',
        'client_id',
        'client_secret',
        'client_secret_expires_at',
        'registration_access_token',
        'registration_client_uri_path',
        'contacts',
        'application_type',
        'client_name',
        'logo_uri',
        'tos_uri',
        'redirect_uris',
        'post_logout_redirect_uris',
        'token_endpoint_auth_method',
        'token_endpoint_auth_signing_alg',
        'policy_uri',
        'jwks_uri',
        'jwks',
        'jwk_encryption_uri',
        'x509_uri',
        'x509_encryption_uri',
        'sector_identifier_uri',
        'subject_type',
        'request_object_signing_alg',
        'userinfo_signed_response_alg',
        'userinfo_encrypted_response_alg',
        'userinfo_encrypted_response_enc',
        'id_token_signed_response_alg',
        'id_token_encrypted_response_alg',
        'id_token_encrypted_response_enc',
        'default_max_age',
        'require_auth_time',
        'default_acr_values',
        'initiate_login_uri',
        'post_logout_redirect_uri',
        'request_uris',
        'grant_types',
        'response_types'
    );

    /**
     * Creates a Doctrine Collection for members.
     */
    public function __construct()
    {
        $this->accounts = new \Doctrine\Common\Collections\ArrayCollection();
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
    public function getClientIdIssuedAt()
    {
        return $this->client_id_issued_at;
    }

    /**
     * @param mixed $client_id_issued_at
     */
    public function setClientIdIssuedAt($client_id_issued_at)
    {
        $this->client_id_issued_at = $client_id_issued_at;
    }

    /**
     * @return mixed
     */
    public function getClientId()
    {
        return $this->client_id;
    }

    /**
     * @param mixed $client_id
     */
    public function setClientId($client_id)
    {
        $this->client_id = $client_id;
    }

    /**
     * @return mixed
     */
    public function getClientSecret()
    {
        return $this->client_secret;
    }

    /**
     * @param mixed $client_secret
     */
    public function setClientSecret($client_secret)
    {
        $this->client_secret = $client_secret;
    }

    /**
     * @return mixed
     */
    public function getClientSecretExpiresAt()
    {
        return $this->client_secret_expires_at;
    }

    /**
     * @param mixed $client_secret_expires_at
     */
    public function setClientSecretExpiresAt($client_secret_expires_at)
    {
        $this->client_secret_expires_at = $client_secret_expires_at;
    }

    /**
     * @return mixed
     */
    public function getRegistrationAccessToken()
    {
        return $this->registration_access_token;
    }

    /**
     * @param mixed $registration_access_token
     */
    public function setRegistrationAccessToken($registration_access_token)
    {
        $this->registration_access_token = $registration_access_token;
    }

    /**
     * @return mixed
     */
    public function getRegistrationClientUriPath()
    {
        return $this->registration_client_uri_path;
    }

    /**
     * @param mixed $registration_client_uri_path
     */
    public function setRegistrationClientUriPath($registration_client_uri_path)
    {
        $this->registration_client_uri_path = $registration_client_uri_path;
    }

    /**
     * @return mixed
     */
    public function getContacts()
    {
        return $this->contacts;
    }

    /**
     * @param mixed $contacts
     */
    public function setContacts($contacts)
    {
        $this->contacts = $contacts;
    }

    /**
     * @return mixed
     */
    public function getApplicationType()
    {
        return $this->application_type;
    }

    /**
     * @param mixed $application_type
     */
    public function setApplicationType($application_type)
    {
        $this->application_type = $application_type;
    }

    /**
     * @return mixed
     */
    public function getClientName()
    {
        return $this->client_name;
    }

    /**
     * @param mixed $client_name
     */
    public function setClientName($client_name)
    {
        $this->client_name = $client_name;
    }

    /**
     * @return mixed
     */
    public function getLogoUri()
    {
        return $this->logo_uri;
    }

    /**
     * @param mixed $logo_uri
     */
    public function setLogoUri($logo_uri)
    {
        $this->logo_uri = $logo_uri;
    }

    /**
     * @return mixed
     */
    public function getTosUri()
    {
        return $this->tos_uri;
    }

    /**
     * @param mixed $tos_uri
     */
    public function setTosUri($tos_uri)
    {
        $this->tos_uri = $tos_uri;
    }

    /**
     * @return mixed
     */
    public function getRedirectUris()
    {
        return $this->redirect_uris;
    }

    /**
     * @param mixed $redirect_uris
     */
    public function setRedirectUris($redirect_uris)
    {
        $this->redirect_uris = $redirect_uris;
    }

    /**
     * @return mixed
     */
    public function getPostLogoutRedirectUris()
    {
        return $this->post_logout_redirect_uris;
    }

    /**
     * @param mixed $post_logout_redirect_uris
     */
    public function setPostLogoutRedirectUris($post_logout_redirect_uris)
    {
        $this->post_logout_redirect_uris = $post_logout_redirect_uris;
    }

    /**
     * @return mixed
     */
    public function getTokenEndpointAuthMethod()
    {
        return $this->token_endpoint_auth_method;
    }

    /**
     * @param mixed $token_endpoint_auth_method
     */
    public function setTokenEndpointAuthMethod($token_endpoint_auth_method)
    {
        $this->token_endpoint_auth_method = $token_endpoint_auth_method;
    }

    /**
     * @return mixed
     */
    public function getTokenEndpointAuthSigningAlg()
    {
        return $this->token_endpoint_auth_signing_alg;
    }

    /**
     * @param mixed $token_endpoint_auth_signing_alg
     */
    public function setTokenEndpointAuthSigningAlg($token_endpoint_auth_signing_alg)
    {
        $this->token_endpoint_auth_signing_alg = $token_endpoint_auth_signing_alg;
    }

    /**
     * @return mixed
     */
    public function getPolicyUri()
    {
        return $this->policy_uri;
    }

    /**
     * @param mixed $policy_uri
     */
    public function setPolicyUri($policy_uri)
    {
        $this->policy_uri = $policy_uri;
    }

    /**
     * @return mixed
     */
    public function getJwksUri()
    {
        return $this->jwks_uri;
    }

    /**
     * @param mixed $jwks_uri
     */
    public function setJwksUri($jwks_uri)
    {
        $this->jwks_uri = $jwks_uri;
    }

    /**
     * @return mixed
     */
    public function getJwkEncryptionUri()
    {
        return $this->jwk_encryption_uri;
    }

    /**
     * @param mixed $jwk_encryption_uri
     */
    public function setJwkEncryptionUri($jwk_encryption_uri)
    {
        $this->jwk_encryption_uri = $jwk_encryption_uri;
    }

    /**
     * @return mixed
     */
    public function getJwks()
    {
        return $this->jwks;
    }

    /**
     * @param mixed $jwks
     */
    public function setJwks($jwks)
    {
        $this->jwks = $jwks;
    }

    /**
     * @return mixed
     */
    public function getX509Uri()
    {
        return $this->x509_uri;
    }

    /**
     * @param mixed $x509_uri
     */
    public function setX509Uri($x509_uri)
    {
        $this->x509_uri = $x509_uri;
    }

    /**
     * @return mixed
     */
    public function getX509EncryptionUri()
    {
        return $this->x509_encryption_uri;
    }

    /**
     * @param mixed $x509_encryption_uri
     */
    public function setX509EncryptionUri($x509_encryption_uri)
    {
        $this->x509_encryption_uri = $x509_encryption_uri;
    }

    /**
     * @return mixed
     */
    public function getSectorIdentifierUri()
    {
        return $this->sector_identifier_uri;
    }

    /**
     * @param mixed $sector_identifier_uri
     */
    public function setSectorIdentifierUri($sector_identifier_uri)
    {
        $this->sector_identifier_uri = $sector_identifier_uri;
    }

    /**
     * @return mixed
     */
    public function getSubjectType()
    {
        return $this->subject_type;
    }

    /**
     * @param mixed $subject_type
     */
    public function setSubjectType($subject_type)
    {
        $this->subject_type = $subject_type;
    }

    /**
     * @return mixed
     */
    public function getRequestObjectSigningAlg()
    {
        return $this->request_object_signing_alg;
    }

    /**
     * @param mixed $request_object_signing_alg
     */
    public function setRequestObjectSigningAlg($request_object_signing_alg)
    {
        $this->request_object_signing_alg = $request_object_signing_alg;
    }

    /**
     * @return mixed
     */
    public function getUserinfoSignedResponseAlg()
    {
        return $this->userinfo_signed_response_alg;
    }

    /**
     * @param mixed $userinfo_signed_response_alg
     */
    public function setUserinfoSignedResponseAlg($userinfo_signed_response_alg)
    {
        $this->userinfo_signed_response_alg = $userinfo_signed_response_alg;
    }

    /**
     * @return mixed
     */
    public function getUserinfoEncryptedResponseAlg()
    {
        return $this->userinfo_encrypted_response_alg;
    }

    /**
     * @param mixed $userinfo_encrypted_response_alg
     */
    public function setUserinfoEncryptedResponseAlg($userinfo_encrypted_response_alg)
    {
        $this->userinfo_encrypted_response_alg = $userinfo_encrypted_response_alg;
    }

    /**
     * @return mixed
     */
    public function getUserinfoEncryptedResponseEnc()
    {
        return $this->userinfo_encrypted_response_enc;
    }

    /**
     * @param mixed $userinfo_encrypted_response_enc
     */
    public function setUserinfoEncryptedResponseEnc($userinfo_encrypted_response_enc)
    {
        $this->userinfo_encrypted_response_enc = $userinfo_encrypted_response_enc;
    }

    /**
     * @return mixed
     */
    public function getIdTokenSignedResponseAlg()
    {
        return $this->id_token_signed_response_alg;
    }

    /**
     * @param mixed $id_token_signed_response_alg
     */
    public function setIdTokenSignedResponseAlg($id_token_signed_response_alg)
    {
        $this->id_token_signed_response_alg = $id_token_signed_response_alg;
    }

    /**
     * @return mixed
     */
    public function getIdTokenEncryptedResponseAlg()
    {
        return $this->id_token_encrypted_response_alg;
    }

    /**
     * @param mixed $id_token_encrypted_response_alg
     */
    public function setIdTokenEncryptedResponseAlg($id_token_encrypted_response_alg)
    {
        $this->id_token_encrypted_response_alg = $id_token_encrypted_response_alg;
    }

    /**
     * @return mixed
     */
    public function getIdTokenEncryptedResponseEnc()
    {
        return $this->id_token_encrypted_response_enc;
    }

    /**
     * @param mixed $id_token_encrypted_response_enc
     */
    public function setIdTokenEncryptedResponseEnc($id_token_encrypted_response_enc)
    {
        $this->id_token_encrypted_response_enc = $id_token_encrypted_response_enc;
    }

    /**
     * @return mixed
     */
    public function getDefaultMaxAge()
    {
        return $this->default_max_age;
    }

    /**
     * @param mixed $default_max_age
     */
    public function setDefaultMaxAge($default_max_age)
    {
        $this->default_max_age = $default_max_age;
    }

    /**
     * @return mixed
     */
    public function getRequireAuthTime()
    {
        return $this->require_auth_time;
    }

    /**
     * @param mixed $require_auth_time
     */
    public function setRequireAuthTime($require_auth_time)
    {
        $this->require_auth_time = $require_auth_time;
    }

    /**
     * @return mixed
     */
    public function getDefaultAcrValues()
    {
        return $this->default_acr_values;
    }

    /**
     * @param mixed $default_acr_values
     */
    public function setDefaultAcrValues($default_acr_values)
    {
        $this->default_acr_values = $default_acr_values;
    }

    /**
     * @return mixed
     */
    public function getInitiateLoginUri()
    {
        return $this->initiate_login_uri;
    }

    /**
     * @param mixed $initiate_login_uri
     */
    public function setInitiateLoginUri($initiate_login_uri)
    {
        $this->initiate_login_uri = $initiate_login_uri;
    }

    /**
     * @return mixed
     */
    public function getPostLogoutRedirectUri()
    {
        return $this->post_logout_redirect_uri;
    }

    /**
     * @param mixed $post_logout_redirect_uri
     */
    public function setPostLogoutRedirectUri($post_logout_redirect_uri)
    {
        $this->post_logout_redirect_uri = $post_logout_redirect_uri;
    }

    /**
     * @return mixed
     */
    public function getRequestUris()
    {
        return $this->request_uris;
    }

    /**
     * @param mixed $request_uris
     */
    public function setRequestUris($request_uris)
    {
        $this->request_uris = $request_uris;
    }

    /**
     * @return mixed
     */
    public function getGrantTypes()
    {
        return $this->grant_types;
    }

    /**
     * @param mixed $grant_types
     */
    public function setGrantTypes($grant_types)
    {
        $this->grant_types = $grant_types;
    }

    /**
     * @return mixed
     */
    public function getResponseTypes()
    {
        return $this->response_types;
    }

    /**
     * @param mixed $response_types
     */
    public function setResponseTypes($response_types)
    {
        $this->response_types = $response_types;
    }

    /**
     * @return mixed
     */
    public function getAccounts()
    {
        return $this->accounts;
    }

    /**
     * @param mixed $Accounts
     */
    public function setAccounts($Accounts)
    {
        $this->accounts = $Accounts;
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


    public function addAccount($account)
    {
        $this->accounts[] = $account;
    }

}
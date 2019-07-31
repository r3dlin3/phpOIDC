<?php
require_once "BaseEntity.php";

use Doctrine\ORM\Mapping as ORM;


/**
 * @ORM\Entity
 * @ORM\Table(name="provider")
 **/
class Provider extends BaseEntity implements JsonSerializable, ArrayAccess
{

    /** @ORM\Id
     *  @ORM\Column(type="integer")
     *  @ORM\GeneratedValue
     **/
    private $id;

    /** @ORM\Column(type="string",length=16, nullable=true, unique=true) **/
    private $key_id;

    /** @ORM\Column(type="text", nullable=true) **/
    private $name;

    /** @ORM\Column(type="string",length=255) **/
    private $url;

    /** @ORM\Column(type="string",length=255) **/
    private $issuer;

    /** @ORM\Column(type="string",length=255) **/
    private $client_id;

    /** @ORM\Column(type="string",length=255) **/
    private $client_secret;

    /** @ORM\Column(type="integer") **/
    private $client_id_issued_at;

    /** @ORM\Column(type="integer") **/
    private $client_secret_expires_at;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $registration_access_token;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $registration_client_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $authorization_endpoint;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $token_endpoint;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $userinfo_endpoint;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $check_id_endpoint;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $check_session_iframe;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $end_session_endpoint;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $jwks_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $jwk_encryption_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $x509_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $x509_encryption_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $registration_endpoint;

    /** @ORM\Column(type="text", nullable=true) **/
    private $scopes_supported;

    /** @ORM\Column(type="text", nullable=true) **/
    private $response_types_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $grant_types_supported;

    /** @ORM\Column(type="text", nullable=true) **/
    private $acr_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $subject_types_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $userinfo_signing_alg_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $userinfo_encryption_alg_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $userinfo_encryption_enc_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $id_token_signing_alg_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $id_token_encryption_alg_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $id_token_encryption_enc_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $request_object_signing_alg_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $request_object_encryption_alg_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $request_object_encryption_enc_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $token_endpoint_auth_methods_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $token_endpoint_auth_signing_alg_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $display_values_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $claim_types_supported;

    /** @ORM\Column(type="text", nullable=true) **/
    private $claims_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $service_documentation;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $claims_locales_supported;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $ui_locales_supported;

    /** @ORM\Column(type="boolean", nullable=true) **/
    private $require_request_uri_registration;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $op_policy_uri;

    /** @ORM\Column(type="string",length=255, nullable=true) **/
    private $op_tos_uri;

    /** @ORM\Column(type="boolean", nullable=true) **/
    private $claims_parameter_supported;

    /** @ORM\Column(type="boolean", nullable=true) **/
    private $request_parameter_supported;

    /** @ORM\Column(type="boolean", nullable=true) **/
    private $request_uri_parameter_supported;

    private static $tableFields = array(
        'id',
        'key_id',
        'name',
        'url',
        'issuer',
        'client_id',
        'client_secret',
        'client_id_issued_at',
        'client_secret_expires_at',
        'registration_access_token',
        'registration_client_uri',
        'authorization_endpoint',
        'token_endpoint',
        'userinfo_endpoint',
        'check_id_endpoint',
        'check_session_iframe',
        'end_session_endpoint',
        'jwks_uri',
        'jwk_encryption_uri',
        'x509_uri',
        'x509_encryption_uri',
        'registration_endpoint',
        'scopes_supported',
        'response_types_supported',
        'grant_types_supported',
        'acr_values_supported',
        'subject_types_supported',
        'userinfo_signing_alg_values_supported',
        'userinfo_encryption_alg_values_supported',
        'userinfo_encryption_enc_values_supported',
        'id_token_signing_alg_values_supported',
        'id_token_encryption_alg_values_supported',
        'id_token_encryption_enc_values_supported',
        'request_object_signing_alg_values_supported',
        'request_object_encryption_alg_values_supported',
        'request_object_encryption_enc_values_supported',
        'token_endpoint_auth_methods_supported',
        'token_endpoint_auth_signing_alg_values_supported',
        'display_values_supported',
        'claim_types_supported',
        'claims_supported',
        'service_documentation',
        'claims_locales_supported',
        'ui_locales_supported',
        'require_request_uri_registration',
        'op_policy_uri',
        'op_tos_uri',
        'claims_parameter_supported',
        'request_parameter_supported',
        'request_uri_parameter_supported'
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
    public function getKeyId()
    {
        return $this->key_id;
    }

    /**
     * @param mixed $key_id
     */
    public function setKeyId($key_id)
    {
        $this->key_id = $key_id;
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
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * @param mixed $url
     */
    public function setUrl($url)
    {
        $this->url = $url;
    }

    /**
     * @return mixed
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * @param mixed $issuer
     */
    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;
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
    public function getRegistrationClientUri()
    {
        return $this->registration_client_uri;
    }

    /**
     * @param mixed $registration_client_uri
     */
    public function setRegistrationClientUri($registration_client_uri)
    {
        $this->registration_client_uri = $registration_client_uri;
    }

    /**
     * @return mixed
     */
    public function getAuthorizationEndpoint()
    {
        return $this->authorization_endpoint;
    }

    /**
     * @param mixed $authorization_endpoint
     */
    public function setAuthorizationEndpoint($authorization_endpoint)
    {
        $this->authorization_endpoint = $authorization_endpoint;
    }

    /**
     * @return mixed
     */
    public function getTokenEndpoint()
    {
        return $this->token_endpoint;
    }

    /**
     * @param mixed $token_endpoint
     */
    public function setTokenEndpoint($token_endpoint)
    {
        $this->token_endpoint = $token_endpoint;
    }

    /**
     * @return mixed
     */
    public function getUserinfoEndpoint()
    {
        return $this->userinfo_endpoint;
    }

    /**
     * @param mixed $userinfo_endpoint
     */
    public function setUserinfoEndpoint($userinfo_endpoint)
    {
        $this->userinfo_endpoint = $userinfo_endpoint;
    }

    /**
     * @return mixed
     */
    public function getCheckIdEndpoint()
    {
        return $this->check_id_endpoint;
    }

    /**
     * @param mixed $check_id_endpoint
     */
    public function setCheckIdEndpoint($check_id_endpoint)
    {
        $this->check_id_endpoint = $check_id_endpoint;
    }

    /**
     * @return mixed
     */
    public function getCheckSessionIframe()
    {
        return $this->check_session_iframe;
    }

    /**
     * @param mixed $check_session_iframe
     */
    public function setCheckSessionIframe($check_session_iframe)
    {
        $this->check_session_iframe = $check_session_iframe;
    }

    /**
     * @return mixed
     */
    public function getEndSessionEndpoint()
    {
        return $this->end_session_endpoint;
    }

    /**
     * @param mixed $end_session_endpoint
     */
    public function setEndSessionEndpoint($end_session_endpoint)
    {
        $this->end_session_endpoint = $end_session_endpoint;
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
    public function getRegistrationEndpoint()
    {
        return $this->registration_endpoint;
    }

    /**
     * @param mixed $registration_endpoint
     */
    public function setRegistrationEndpoint($registration_endpoint)
    {
        $this->registration_endpoint = $registration_endpoint;
    }

    /**
     * @return mixed
     */
    public function getScopesSupported()
    {
        return $this->scopes_supported;
    }

    /**
     * @param mixed $scopes_supported
     */
    public function setScopesSupported($scopes_supported)
    {
        $this->scopes_supported = $scopes_supported;
    }

    /**
     * @return mixed
     */
    public function getResponseTypesSupported()
    {
        return $this->response_types_supported;
    }

    /**
     * @param mixed $response_types_supported
     */
    public function setResponseTypesSupported($response_types_supported)
    {
        $this->response_types_supported = $response_types_supported;
    }

    /**
     * @return mixed
     */
    public function getGrantTypesSupported()
    {
        return $this->grant_types_supported;
    }

    /**
     * @param mixed $grant_types_supported
     */
    public function setGrantTypesSupported($grant_types_supported)
    {
        $this->grant_types_supported = $grant_types_supported;
    }

    /**
     * @return mixed
     */
    public function getAcrValuesSupported()
    {
        return $this->acr_values_supported;
    }

    /**
     * @param mixed $acr_values_supported
     */
    public function setAcrValuesSupported($acr_values_supported)
    {
        $this->acr_values_supported = $acr_values_supported;
    }

    /**
     * @return mixed
     */
    public function getSubjectTypesSupported()
    {
        return $this->subject_types_supported;
    }

    /**
     * @param mixed $subject_types_supported
     */
    public function setSubjectTypesSupported($subject_types_supported)
    {
        $this->subject_types_supported = $subject_types_supported;
    }

    /**
     * @return mixed
     */
    public function getUserinfoSigningAlgValuesSupported()
    {
        return $this->userinfo_signing_alg_values_supported;
    }

    /**
     * @param mixed $userinfo_signing_alg_values_supported
     */
    public function setUserinfoSigningAlgValuesSupported($userinfo_signing_alg_values_supported)
    {
        $this->userinfo_signing_alg_values_supported = $userinfo_signing_alg_values_supported;
    }

    /**
     * @return mixed
     */
    public function getUserinfoEncryptionAlgValuesSupported()
    {
        return $this->userinfo_encryption_alg_values_supported;
    }

    /**
     * @param mixed $userinfo_encryption_alg_values_supported
     */
    public function setUserinfoEncryptionAlgValuesSupported($userinfo_encryption_alg_values_supported)
    {
        $this->userinfo_encryption_alg_values_supported = $userinfo_encryption_alg_values_supported;
    }

    /**
     * @return mixed
     */
    public function getUserinfoEncryptionEncValuesSupported()
    {
        return $this->userinfo_encryption_enc_values_supported;
    }

    /**
     * @param mixed $userinfo_encryption_enc_values_supported
     */
    public function setUserinfoEncryptionEncValuesSupported($userinfo_encryption_enc_values_supported)
    {
        $this->userinfo_encryption_enc_values_supported = $userinfo_encryption_enc_values_supported;
    }

    /**
     * @return mixed
     */
    public function getIdTokenSigningAlgValuesSupported()
    {
        return $this->id_token_signing_alg_values_supported;
    }

    /**
     * @param mixed $id_token_signing_alg_values_supported
     */
    public function setIdTokenSigningAlgValuesSupported($id_token_signing_alg_values_supported)
    {
        $this->id_token_signing_alg_values_supported = $id_token_signing_alg_values_supported;
    }

    /**
     * @return mixed
     */
    public function getIdTokenEncryptionAlgValuesSupported()
    {
        return $this->id_token_encryption_alg_values_supported;
    }

    /**
     * @param mixed $id_token_encryption_alg_values_supported
     */
    public function setIdTokenEncryptionAlgValuesSupported($id_token_encryption_alg_values_supported)
    {
        $this->id_token_encryption_alg_values_supported = $id_token_encryption_alg_values_supported;
    }

    /**
     * @return mixed
     */
    public function getIdTokenEncryptionEncValuesSupported()
    {
        return $this->id_token_encryption_enc_values_supported;
    }

    /**
     * @param mixed $id_token_encryption_enc_values_supported
     */
    public function setIdTokenEncryptionEncValuesSupported($id_token_encryption_enc_values_supported)
    {
        $this->id_token_encryption_enc_values_supported = $id_token_encryption_enc_values_supported;
    }

    /**
     * @return mixed
     */
    public function getRequestObjectSigningAlgValuesSupported()
    {
        return $this->request_object_signing_alg_values_supported;
    }

    /**
     * @param mixed $request_object_signing_alg_values_supported
     */
    public function setRequestObjectSigningAlgValuesSupported($request_object_signing_alg_values_supported)
    {
        $this->request_object_signing_alg_values_supported = $request_object_signing_alg_values_supported;
    }

    /**
     * @return mixed
     */
    public function getRequestObjectEncryptionAlgValuesSupported()
    {
        return $this->request_object_encryption_alg_values_supported;
    }

    /**
     * @param mixed $request_object_encryption_alg_values_supported
     */
    public function setRequestObjectEncryptionAlgValuesSupported($request_object_encryption_alg_values_supported)
    {
        $this->request_object_encryption_alg_values_supported = $request_object_encryption_alg_values_supported;
    }

    /**
     * @return mixed
     */
    public function getRequestObjectEncryptionEncValuesSupported()
    {
        return $this->request_object_encryption_enc_values_supported;
    }

    /**
     * @param mixed $request_object_encryption_enc_values_supported
     */
    public function setRequestObjectEncryptionEncValuesSupported($request_object_encryption_enc_values_supported)
    {
        $this->request_object_encryption_enc_values_supported = $request_object_encryption_enc_values_supported;
    }

    /**
     * @return mixed
     */
    public function getTokenEndpointAuthMethodsSupported()
    {
        return $this->token_endpoint_auth_methods_supported;
    }

    /**
     * @param mixed $token_endpoint_auth_methods_supported
     */
    public function setTokenEndpointAuthMethodsSupported($token_endpoint_auth_methods_supported)
    {
        $this->token_endpoint_auth_methods_supported = $token_endpoint_auth_methods_supported;
    }

    /**
     * @return mixed
     */
    public function getTokenEndpointAuthSigningAlgValuesSupported()
    {
        return $this->token_endpoint_auth_signing_alg_values_supported;
    }

    /**
     * @param mixed $token_endpoint_auth_signing_alg_values_supported
     */
    public function setTokenEndpointAuthSigningAlgValuesSupported($token_endpoint_auth_signing_alg_values_supported)
    {
        $this->token_endpoint_auth_signing_alg_values_supported = $token_endpoint_auth_signing_alg_values_supported;
    }

    /**
     * @return mixed
     */
    public function getDisplayValuesSupported()
    {
        return $this->display_values_supported;
    }

    /**
     * @param mixed $display_values_supported
     */
    public function setDisplayValuesSupported($display_values_supported)
    {
        $this->display_values_supported = $display_values_supported;
    }

    /**
     * @return mixed
     */
    public function getClaimTypesSupported()
    {
        return $this->claim_types_supported;
    }

    /**
     * @param mixed $claim_types_supported
     */
    public function setClaimTypesSupported($claim_types_supported)
    {
        $this->claim_types_supported = $claim_types_supported;
    }

    /**
     * @return mixed
     */
    public function getClaimsSupported()
    {
        return $this->claims_supported;
    }

    /**
     * @param mixed $claims_supported
     */
    public function setClaimsSupported($claims_supported)
    {
        $this->claims_supported = $claims_supported;
    }

    /**
     * @return mixed
     */
    public function getServiceDocumentation()
    {
        return $this->service_documentation;
    }

    /**
     * @param mixed $service_documentation
     */
    public function setServiceDocumentation($service_documentation)
    {
        $this->service_documentation = $service_documentation;
    }

    /**
     * @return mixed
     */
    public function getClaimsLocalesSupported()
    {
        return $this->claims_locales_supported;
    }

    /**
     * @param mixed $claims_locales_supported
     */
    public function setClaimsLocalesSupported($claims_locales_supported)
    {
        $this->claims_locales_supported = $claims_locales_supported;
    }

    /**
     * @return mixed
     */
    public function getUiLocalesSupported()
    {
        return $this->ui_locales_supported;
    }

    /**
     * @param mixed $ui_locales_supported
     */
    public function setUiLocalesSupported($ui_locales_supported)
    {
        $this->ui_locales_supported = $ui_locales_supported;
    }

    /**
     * @return mixed
     */
    public function getRequireRequestUriRegistration()
    {
        return $this->require_request_uri_registration;
    }

    /**
     * @param mixed $require_request_uri_registration
     */
    public function setRequireRequestUriRegistration($require_request_uri_registration)
    {
        $this->require_request_uri_registration = $require_request_uri_registration;
    }

    /**
     * @return mixed
     */
    public function getOpPolicyUri()
    {
        return $this->op_policy_uri;
    }

    /**
     * @param mixed $op_policy_uri
     */
    public function setOpPolicyUri($op_policy_uri)
    {
        $this->op_policy_uri = $op_policy_uri;
    }

    /**
     * @return mixed
     */
    public function getOpTosUri()
    {
        return $this->op_tos_uri;
    }

    /**
     * @param mixed $op_tos_uri
     */
    public function setOpTosUri($op_tos_uri)
    {
        $this->op_tos_uri = $op_tos_uri;
    }

    /**
     * @return mixed
     */
    public function getClaimsParameterSupported()
    {
        return $this->claims_parameter_supported;
    }

    /**
     * @param mixed $claims_parameter_supported
     */
    public function setClaimsParameterSupported($claims_parameter_supported)
    {
        $this->claims_parameter_supported = $claims_parameter_supported;
    }

    /**
     * @return mixed
     */
    public function getRequestParameterSupported()
    {
        return $this->request_parameter_supported;
    }

    /**
     * @param mixed $request_parameter_supported
     */
    public function setRequestParameterSupported($request_parameter_supported)
    {
        $this->request_parameter_supported = $request_parameter_supported;
    }

    /**
     * @return mixed
     */
    public function getRequestUriParameterSupported()
    {
        return $this->request_uri_parameter_supported;
    }

    /**
     * @param mixed $request_uri_parameter_supported
     */
    public function setRequestUriParameterSupported($request_uri_parameter_supported)
    {
        $this->request_uri_parameter_supported = $request_uri_parameter_supported;
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
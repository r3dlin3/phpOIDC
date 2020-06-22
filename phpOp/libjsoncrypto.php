<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
require_once(__DIR__.'/libs/autoload.php');
include_once(__DIR__."/base64url.php");

$signing_alg_values_supported = Array('none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512');
$encryption_alg_values_supported = Array('RSA1_5', 'RSA-OAEP');
$encryption_enc_values_supported = Array('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM');

/**
* signs a JSON object or string
* @param    mixed  $data               JSON encoded string or JSON object
* @param    array  $arr_sig_params     array of signature params
* if algoritm is HMAC-SHA256 =>
* [
*   { 
*       'alg' : 'HMAC-SHA256',                   # required
*       'kid'    : 'example.com'                    # required
*   }
* ]
*                      
* if algoritme is RSA-SHA256 =>
 *
* [
*   { 
*       'alg'    : 'RSA-SHA256',                   # optional / default value
*       'x5u'    : 'http://example.com/cert.pem'   # required
*       'x5t'    : ''                              # optional/ base64url encoded sha1 of DER encoded public certificate
*   }                        
* ]
*
* @param    array   $arr_keys           array of secrets and/or array of private key files paths and pass phrases
* order must elements must correspond with $arr_sig_params elements.
* if the $arr_sig_params element specifies the algorithm as HMAC-SH256, then you must supply the corresponding HMAC secret
* if the $arr_sig_params element speicfies the algorithm as RSA-SHA256, then you must supply a path to the private key file used for signing and the pass phrase for the key
* [ 
*   'aaaa', 
*   'bbbbb',
*   {
*       'key_file' : '/home/www/server.key',
*       'password'   : 'my_key_pass'
*   }
* ]
*
* @param    int     $use_web_token_serialization    specifies whether to use JSON encoding or web token serialization encoding
* @return   string  the signed JSON object or signed web token serialization encoded as a string
*/

function jwt_sign($data, $sig_param, $keys) {
    $jwt_payload = base64url_encode(is_array($data) ? json_encode($data) : $data);
    $jwt_header = '';
    $header = array();
    $sig = NULL;
    if(array_key_exists('alg', $sig_param)) {
        $alg = strtoupper($sig_param['alg']);
        switch ($alg) {
            case 'RS256' :
            case 'RS384' :
            case 'RS512' :
                if(is_array($keys)) {
                    $header['alg'] = $alg;
                    $headers = array('x5u', 'x5t', 'jku', 'jwk', 'x5c', 'kid', 'typ', 'cty');
                    foreach($headers as $header_name) {
                        if(isset($sig_param[$header_name]))
                            $header[$header_name] = $sig_param[$header_name];
                    }
                    $jwt_header = base64url_encode(json_encode($header));
                    if(isset($keys['key_file'])) {
                        $priv_key_data = file_get_contents($keys['key_file']);
                        $pkey = openssl_pkey_get_private($priv_key_data, $keys['password']);
                        if($pkey) {
                            digest_sign_data("{$jwt_header}.{$jwt_payload}" , $pkey, $sig, 'sha' . substr($alg, 2));
                            openssl_pkey_free($pkey);
                        }
                    } else return false;
                }
                break;

            case 'HS256' :
            case 'HS384' :
            case 'HS512' :
                $header['alg'] = $alg;
                if(isset($sig_param['kid']))
                    $header['kid'] = $sig_param['kid'];
                $jwt_header = base64url_encode(json_encode($header));
                $sig = hash_hmac('sha' . substr($alg, 2), "{$jwt_header}.{$jwt_payload}", $keys, true);
                break;

            case 'NONE' :
                $header['alg'] = 'none';
                $jwt_header = base64url_encode(json_encode($header));
                $sig = '';
                break;

            default:
                return false;
                break;

        }            
    }
    $jwt_sig = $sig ? base64url_encode($sig) : $sig;
    $jwt = "{$jwt_header}.{$jwt_payload}.{$jwt_sig}";
    
    return $jwt;
    
    
}



function jwk_get_keys($jwk, $kty = 'RSA', $use = NULL, $kid = NULL, $x5t = NULL) {
    if(is_string($jwk))
        $json = json_decode($jwk, true);
    else
        $json = $jwk;
    if(!isset($json['keys']))
        return NULL;
    if(!count($json['keys']))
        return NULL;
    $foundkeys = array();
    foreach($json['keys'] as $key) {
        if(!strcmp($key['kty'], $kty)) {
            $foundkeys[] = $key;
        }
    }
    if(!count($foundkeys))
        return NULL;
    if($use) {
        $temp = array();
        foreach($foundkeys as $key) {
            if(!$key['use'])
                $temp[] = $key;
            elseif(!strcmp($key['use'], $use))
                array_unshift($temp, $key);
        }
        $foundkeys = $temp;
    }
    if(!count($foundkeys))
        return NULL;
    if(isset($kid)) {
        $temp = array();
        foreach($foundkeys as $key) {
            if(!strcmp($key['kid'], $kid))
                $temp[] = $key;
        }
        $foundkeys = $temp;
    }
    if(isset($x5t)) {
        $temp = array();
        foreach($foundkeys as $key) {
            if(!strcmp($key['x5t'], $x5t))
                $temp[] = $key;
        }
        $foundkeys = $temp;
    }
    return $foundkeys;
}

function jwk_get_rsa_use_key($jwk, $use = NULL, $kid = NULL, $x5t = NULL) {
    $is_cert = false;
    $keys = jwk_get_keys($jwk, 'RSA', $use, $kid, $x5t);
    if(!count($keys)) {
        return NULL;
    }
    $rsa_key = $keys[0];
    $rsa = NULL;
    if($rsa_key) {
        if(isset($rsa_key['n']) && isset($rsa_key['e'])) {
            $modulus = new \phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($rsa_key['n'])), 16);
            $exponent = new \phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($rsa_key['e'])), 16);
            $rsa = new \phpseclib\Crypt\RSA();
            $rsa->modulus = $modulus;
            $rsa->exponent = $exponent;
            $rsa->publicExponent = $exponent;
            $rsa->k = strlen($rsa->modulus->toBytes());
        } else if(isset($rsa_key['x5c'])) {
            $key_contents = "-----BEGIN CERTIFICATE-----\n" . $rsa_key['x5c'][0] . "\n-----END CERTIFICATE-----\n";
            $key = openssl_pkey_get_public($key_contents);
            if($key) {
                $details = openssl_pkey_get_details($key);
                $pubkey = $details['key'];
                $rsa = new \phpseclib\Crypt\RSA();
                if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                    return false;
            }
        }
    }
    return $rsa;
}

function jwk_get_rsa_sig_key($jwk, $kid = NULL, $x5t = NULL) {
    return jwk_get_rsa_use_key($jwk, 'sig', $kid, $x5t);
}

function jwk_get_rsa_enc_key($jwk, $kid = NULL, $x5t = NULL) {
    return jwk_get_rsa_use_key($jwk, 'enc', $kid, $x5t);
}


function parse_key_hints($sig_hints) {
    $pems = array();
    $jwks = array();
    $vals = array();
    
    foreach($sig_hints as $key => $value) {
        switch((string)$key) {
            
            case 'x5c' : // X509 cert chain
                if(is_array($value))
                    $pems = array_merge($pems, $value);
                else
                    $pems[] = $value;
                    // print_r($value);
            break;

            case 'x5u' : // X509 URL
                $pem = get_url_contents($value);
                if($pem) {
                    $pems[] = $pem;
                }
            break;
            
            case 'pem': // x509 file or directory
                if(is_file($sig_hints['pem'])) {
                    $pems[] = file_get_contents($sig_hints['pem']);
                } elseif(is_dir($sig_hints['pem'])) {
                    foreach(glob($sig_hints['pem'] . '/*.pem') as $filename) {
                        $pems[] = file_get_contents($filename);
                    }
                }
    
            break;
            
            case 'jku': // JWK URL
                $jwk = get_url_contents($value);
                if($jwk) {
                    $jwks[] = $jwk;
                }
            break;
            
            case 'jwk': // JWK 
                if(is_array($value))
                    $jwks = array_merge($jwks, $value);
                else
                    $jwks[] = $value;
            break;
            
            default:
                if(is_int($key)) {
                    if(is_array($value)) {
                        list($p, $j, $v) = parse_key_hints($value);
                        $pems = array_merge($pems, $p);
                        $jwks = array_merge($jwks, $j);
                        $vals = array_merge($vals, $v);
                    } else
                        $vals[] = $value;
                }
            break;
        }
    }
    return array($pems, $jwks, $vals);
}

/**
 * Verifies a signed JSON object or string
 * @param  mixed    $jss        signed JSON object or string
 * @param  array    $sig_hints  array of signature verification hints.  this is mainly used for HMAC-256 verification
 *                  Each hint is a hash that contains the keys algorithm, key_id, and secret for the HMAC
 *                  [ 
 *                    [
 *                      'algorithm' => 'HMAC-256',
 *                      'key_id'    => 'example.com',
 *                      'secret'    => 'my_hmac_secret'
 *                    ]
 *                  ]
 * @param  array    $allowed_algs        array of allowed/acceptable signature algs
 * @return bool     True if the signatures are verified successfully and False if the signature verification fails
 */
function jwt_verify($jwt, $sig_hints = NULL, $allowed_algs=NULL) {
    $is_compact = false;
    if(is_array($jwt))
        $json_obj = $jwt;
    elseif(is_string($jwt)) {
        if($jwt[0] == '{') { // use { as indicator of json encoded string - JSON serialization
            $json_obj = json_decode($jwt, true);
        }
        else {  // assumes that it's jwt compact serialization
            $pattern = '/^(.+)\.(.+)\.(.*)$/';
            if(preg_match($pattern, $jwt, $matches, PREG_OFFSET_CAPTURE)) {
                $is_compact = true;
                $json_obj = array();
                $json_obj['header'] = array($matches[1][0]);
                $json_obj['payload'] = $matches[2][0];
                $json_obj['signature'] = array($matches[3][0]);
            }
        }
    }
    else return false;
    if(!$json_obj) {
        return false;
    }
        
    if(!isset($json_obj['header']) || !isset($json_obj['payload']) || !isset($json_obj['signature'])) {
        return false;
    }
    
    $headers = json_decode(base64url_decode($json_obj['header'][0]), true);
    $payload = json_decode(base64url_decode($json_obj['payload']), true);
    $sigs = json_decode(base64url_decode($json_obj['signature'][0]), true);
    

    $num_sigs = count($json_obj['signature']);
    $payload = json_decode(base64url_decode($json_obj['payload']), true);
    for($i = 0; $i < $num_sigs; $i++) {
        $header = json_decode(base64url_decode($json_obj['header'][$i]), true);
        $sig = base64url_decode($json_obj['signature'][$i]);
        
            
        if(!isset($header['alg']))
            return false;
        if(!empty($allowed_algs)) {
            if(!is_array($allowed_algs))
                $allowed_algs = array($allowed_algs);
            if(!in_array($header['alg'], $allowed_algs))
                return false;  // using alg that is not allowed/supported
        }
            
        switch($header['alg']) {
            case 'RS256' :
            case 'RS384' :
            case 'RS512' :
                $pems = array();
                $jwks = array();
                $vals = array();
                if($sig_hints) {
                    if(is_array($sig_hints)) {
                        list($p, $j, $v) = parse_key_hints($sig_hints);
                        $pems = array_merge($pems, $p);
                        $jwks = array_merge($jwks, $j);
                        $vals = array_merge($vals, $v);
                    }
                    else {
                        $pems[] = $sig_hints;
                    }
                }
                if(isset($header['x5u']) ) {
                    $pem = get_url_contents($header['x5u']);
                    if($pem) {
                        $pems[] = $pem;
                    }
                }
                if(isset($header['x5c']) ) {
                    $pems[] = $header['x5c'];
                }
                if(isset($header['jku']) ) {
                    $jwk = get_url_contents($header['jku']);
                    if($jwk) {
                        $jwks[] = $jwk;
                    }
                }                
                if(isset($header['jwk']) ) {
                    $jwks[] = $header['jwk'];
                }

                $verified = false;
                $num_pems = count($pems);
                foreach($pems as $pem) {
                    $pubkeyid = openssl_get_publickey($pem);
                    if(!$pubkeyid) {
                        return false;
                    }
                    $status = digest_verify_data("{$json_obj['header'][$i]}.{$json_obj['payload']}", $sig, $pubkeyid, 'sha' . substr($header['alg'], 2) );
                    openssl_free_key($pubkeyid);
                    if($status) {
                        $verified = true;
                        break;
                    }
                }
                if(!$verified) {
                    foreach($jwks as $jwk) {
                        $rsa = jwk_get_rsa_sig_key($jwk, isset($header['kid']) ? $header['kid'] : null, isset($header['x5t']) ? $header['x5t'] : null);
                        if($rsa) {
                            $rsa->setHash('sha' . substr($header['alg'], 2));
                            $rsa->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PKCS1);
                            $status = $rsa->verify("{$json_obj['header'][$i]}.{$json_obj['payload']}", $sig);
                            if($status) {
                                $verified = true;
                                break;
                            }
                        }
                    }
                }
                return $verified;
                
            break;
            
            case 'HS256' :
            case 'HS384' :
            case 'HS512' :
            
            if($sig_hints) {
                if(!is_array($sig_hints)) {
                    $sig_hints = array($sig_hints);
                }
            }
            $num_hints = $sig_hints ? count($sig_hints) : 0;
            if(!$num_hints) {
                return false;
            }
            $verified = false;
            for($j = 0; $j < $num_hints; $j++) {
                if(is_array($sig_hints[$j]) ) {
                    if(isset($sig_hints[$j]['pem'])) {
                        continue;
                    } else
                        $hint = $sig_hints[$j];
                }
                else
                    $hint = array('secret' => $sig_hints[$j]);
                
                if(isset($header['kid']) && isset($hint['kid'])) {
                    if(strcasecmp($header['kid'], $hint['kid']) == 0) {
                        $kid = $sig_hints[$j]['secret'];
                    }
                    else
                        continue;
                } else {
                    $kid = $hint['secret'];
                }
                if(!$kid) {
                    return false;
                }
                
                $data = "{$json_obj['header'][$i]}.{$json_obj['payload']}";
                $calculated_sig = hash_hmac('sha' . substr($header['alg'], 2), $data, $kid, true);
                
                if(strcmp($sig, $calculated_sig) == 0) {
                    $verified = true;
                    break;
                }
            }
            if(!$verified) {
                return false;
            }
            break;

            case 'none' :
            break;
            
            default:
                return false;
        }
        
        
    }
    return true;
}


/**
 * Obtain the content of the URL. 
 * @param  String $url      URL from which the content should be obtained. 
 * @return String Response Text. 
 */
function get_url_contents($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $responseText = curl_exec($ch);
    $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if($http_status != 200) {
        if($responseText && substr($url,0, 7) == 'file://')
            return $responseText;
        return NULL;
    } else {
        return $responseText;
    }
}



/**
 * AES CBC encrypt data with a symmetric key of the specified size
 * @param  String $data             Data to be encrypted
 * @param  String $key              symmetric key, key length must be 16 for key strength 128 and 32 for key strength of 256
 * @param  Int    $key_strength     size of key (128/256)
 * @param  String $iv               initialization vector
 * @return String                   encrypted data
 */
function aes_cbc_encrypt($data, $key, $key_strength, $iv=NULL) {
    $method = '';
    switch ($key_strength) {
        case 128 :
            if(strlen($key) != 16) {
                return NULL;
            }
            $method = 'aes-128-cbc';
            break;

        case 256:
            if(strlen($key) != 32) {
                return NULL;
            }
            $method = 'aes-256-cbc';
            break;

        default:
            return NULL;
    }

    $iv_size = openssl_cipher_iv_length($method);

    if(!$iv && $iv_size) {
        $iv = str_repeat(chr(0), $iv_size);  // initialize to $iv_size byte string of "0"s
    } elseif($iv && $iv_size != strlen($iv)) {
        return NULL;
    }
    return openssl_encrypt($data, $method, $key, OPENSSL_RAW_DATA, $iv);
}

/**
 * AES CBC decrypt data with a symmetric key of the specified size
 * @param  String $data             encrypted data
 * @param  String $key              symmetric key, key length must be 16 for key strength 128 and 32 for key strength of 256
 * @param  Int    $key_strength     size of key (128/256)
 * @param  String $iv               initialization vector
 * @return String                   decrypted data
 */
function aes_cbc_decrypt($data, $key, $key_strength, $iv=NULL) {

    $method = '';
    switch ($key_strength) {
        case 128 :
            if(strlen($key) != 16) {
                return NULL;
            }
            $method = 'aes-128-cbc';
            break;

        case 256:
            if(strlen($key) != 32) {
                return NULL;
            }
            $method = 'aes-256-cbc';
            break;

        default:
            return NULL;
    }

    $iv_size = openssl_cipher_iv_length($method);

    if(!$iv && $iv_size) {
        $iv = str_repeat(chr(0), $iv_size);  // initialize to $iv_size byte string of "0"s
    } elseif($iv && $iv_size != strlen($iv)) {
        return NULL;
    }
    return openssl_decrypt($data, $method, $key, OPENSSL_RAW_DATA, $iv);
}


/**
 * AES CBC encrypt data with a 128 bit symmetric key
 * @param  String $data             Data to be encrypted
 * @param  String $key              symmetric key, key length must be 16
 * @param  String $iv               initialization vector
 * @return String                   encrypted data
 */
function aes_128_cbc_encrypt($data, $key, $iv = NULL) {
    return aes_cbc_encrypt($data, $key, 128, $iv);
}


/**
 * AES CBC encrypt data with a 256 bit symmetric key
 * @param  String $data             Data to be encrypted
 * @param  String $key              symmetric key, key length must be 32
 * @param  String $iv               initialization vector
 * @return String                   encrypted data
 */
function aes_256_cbc_encrypt($data, $key, $iv = NULL) {
    return aes_cbc_encrypt($data, $key, 256, $iv);
}

/**
 * AES CBC decrypt data with a 128 bit symmetric key
 * @param  String $data             encrypted data
 * @param  String $key              symmetric key, key length must be 16
 * @param  String $iv               initialization vector
 * @return String                   decrypted data
 */
function aes_128_cbc_decrypt($data, $key, $iv = NULL) {
    return aes_cbc_decrypt($data, $key, 128, $iv);
}


/**
 * AES CBC decrypt data with a 256 bit symmetric key
 * @param  String $data             encrypted data
 * @param  String $key              symmetric key, key length must be 32
 * @param  String $iv               initialization vector
 * @return String                   decrypted data
 */
function aes_256_cbc_decrypt($data, $key, $iv = NULL) {
    return aes_cbc_decrypt($data, $key, 256, $iv);
}


/**
 * Perform RSA 1.5 encryption with PKCS1_PADDING with given private or public key
 * @param  String $data             data to be encrypted
 * @param  String $key_file         path to public or private key or string consisting of PEM encoded key
 * @param  bool   $is_private_key   boolean to denote wheter key is private or not
 * @param  String $pass_phrase      pass phrase for private key
 * @return String                   encrypted data
 */

function encrypt_with_key($data, $key_file,  $is_private_key=true, $pass_phrase=NULL, $alg = 'RSA1_5') {
    $is_jwk = false;
//    print_r($key_file);
    if(is_array($key_file)) {
        $is_jwk = true;
        $key_contents = $key_file;
    }
    elseif(is_file($key_file)) {
        if(!file_exists($key_file)) return false;
        $key_contents = file_get_contents($key_file);
    } else
        $key_contents = $key_file;
    if($is_private_key)
        $key = openssl_pkey_get_private($key_contents, $pass_phrase);
    else {
        if(!$is_jwk)
            $key = openssl_pkey_get_public($key_contents);
    }
    if(!$key && !$is_jwk) {
        return false;
    }
    $cipherText = NULL;
    $status = false;
    $use_openssl = false;
    switch($alg) {
        case 'RSA1_5':
            if($use_openssl) {
                if($is_private_key) 
                    $status = openssl_private_encrypt($data, $cipherText, $key, OPENSSL_PKCS1_PADDING);
                else
                    $status = openssl_public_encrypt($data, $cipherText, $key);
            } else {
                $rsa = new \phpseclib\Crypt\RSA();
                if($rsa) {
                    if($is_private_key) {
                        $rsa->setPassword($pass_phrase);
                        if(!$rsa->loadkey($key_contents, \phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1))
                            return false;
                    }
                    else {
                        if($is_jwk) {
                            if($key_contents['x5c']) {
                                $cert = "-----BEGIN CERTIFICATE-----\n" . $key_contents['x5c'][0] . "\n-----END CERTIFICATE-----\n";
                                $key = openssl_pkey_get_public($cert);
                                if($key) {
                                    $details = openssl_pkey_get_details($key);
                                    $pubkey = $details['key'];
                                    if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                                        return false;
                                }
                    
                            } else {
                                if(isset($key_contents['n']) && isset($key_contents['e'])) {
                                    $modulus = new phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($key_contents['n'])), 16);
                                    $exponent = new phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($key_contents['e'])), 16);
                                    $rsa->modulus = $modulus;
                                    $rsa->exponent = $exponent;
                                    $rsa->publicExponent = $exponent;
                                    $rsa->k = strlen($rsa->modulus->toBytes());
                                }            
                            }
                    
                            
                        } else {
                            $details = openssl_pkey_get_details($key);
                            $pubkey = $details['key'];
                            if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                                return false;
                        }
                    }
                    $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);
                    $status = $rsa->encrypt($data);
                    $cipherText = $status;               
                }
            }
        break;
        
        case 'RSA-OAEP':
        $rsa = new \phpseclib\Crypt\RSA();
        if($rsa) {
            if($is_private_key) {
                $rsa->setPassword($pass_phrase);
                if(!$rsa->loadkey($key_contents, \phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1))
                    return false;
            }
            else {

                if($is_jwk) {
                    if($key_contents['x5c']) {
                        $cert = "-----BEGIN CERTIFICATE-----\n" . $key_contents['x5c'][0] . "\n-----END CERTIFICATE-----\n";
                        $key = openssl_pkey_get_public($cert);
                        if($key) {
                            $details = openssl_pkey_get_details($key);
                            $pubkey = $details['key'];
                            if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                                return false;
                        }
            
                    } else {
                        if(isset($key_contents['n']) && isset($key_contents['e'])) {
                            $modulus = new phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($key_contents['n'])), 16);
                            $exponent = new phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($key_contents['e'])), 16);
                            $rsa->modulus = $modulus;
                            $rsa->exponent = $exponent;
                            $rsa->publicExponent = $exponent;
                            $rsa->k = strlen($rsa->modulus->toBytes());
                        }            
                    }
            
                    
                } else {
                    $details = openssl_pkey_get_details($key);
                    $pubkey = $details['key'];
                    if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                        return false;
                }
            }
            $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
            $rsa->setHash('sha1');
            $rsa->setMGFHash('sha1');
            $status = $rsa->encrypt($data);
            $cipherText = $status;
        }
        
        break;
        
        default :
        return false;
        break;
    }
    if(!$status) {
        if($use_openssl)
            openssl_free_key($key);
        return false;
    }
    return $cipherText;
}

/**
 * Perform RSA 1.5 decryption with PKCS1_PADDING with given private or public key
 * @param  String $data             encrypted data to be decrypted
 * @param  String $key_file         path to public or private key or string consisting of PEM encoded key
 * @param  bool   $is_private_key   boolean to denote wheter key is private or not
 * @param  String $pass_phrase      pass phrase for private key
 * @return String                   decrypted data
 */

function decrypt_with_key($data, $key_file, $is_private_key=true, $pass_phrase=NULL, $alg = 'RSA1_5') {
    if(is_string($key_file) && is_file($key_file)) {
        if(!file_exists($key_file)) return false;
        $key_contents = file_get_contents($key_file);
    } else
        $key_contents = $key_file;
    if($is_private_key)
        $key = openssl_pkey_get_private($key_contents, $pass_phrase);
    else 
        $key = openssl_pkey_get_public($key_contents);
    if(!$key) {
        $msg = sprintf("decrypt_with_key - Unable to get %s key\n%s\n", $is_private_key ? 'private' : 'public', $key_file);
        return false;
    }
    $plainText = NULL;
    $status = false;
    $use_openssl = false;
    
    switch($alg) {
        case 'RSA1_5':
        if($use_openssl) {
            if($is_private_key) 
                $status = openssl_private_decrypt($data, $plainText, $key, OPENSSL_PKCS1_PADDING);
            else
                $status = openssl_public_decrypt($data, $plainText, $key);
        } else {
            $rsa = new \phpseclib\Crypt\RSA();
            if($rsa) {
                if($is_private_key) {
                    $rsa->setPassword($pass_phrase);
                    if(!$rsa->loadkey($key_contents, \phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1))
                        return false;
                }
                else {
                    $details = openssl_pkey_get_details($key);
                    $pubkey = $details['key'];
                    if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                        return false;
                }
                $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);
                $status = $rsa->decrypt($data);
                $plainText = $status;               
            }
        }

        break;
        
        case 'RSA-OAEP':
        $rsa = new \phpseclib\Crypt\RSA();
        if($rsa) {
            if($is_private_key) {
                $rsa->setPassword($pass_phrase);
                if(!$rsa->loadkey($key_contents, \phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1))
                    return false;
            }
            else {
                $details = openssl_pkey_get_details($key);
                $pubkey = $details['key'];
                if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                    return false;
            }
            $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
            $rsa->setHash('sha1');
            $rsa->setMGFHash('sha1');
            $status = $rsa->decrypt($data);
            $plainText = $status;
        }
        break;
        
        default:
        return false;
    }
    
    if(!$status) {
        if($use_openssl)
            openssl_free_key($key);
        return false;
    }
    return $plainText;
}



function jwt_encrypt2($data, $key_file, $is_private_key=false, $pass_phrase=NULL, $params=NULL, $enc_key=NULL, $alg='RSA1_5', $enc='A256CBC-HS512', $zip = true) {
    global $encryption_alg_values_supported, $encryption_enc_values_supported;
    if(is_string($key_file) && is_file($key_file)) {
        if(!file_exists($key_file)) {
            return false;
        }
    }
    if(!$alg || !in_array($alg, $encryption_alg_values_supported)) {
        return false;
    }
    if(!$enc || !in_array($enc, $encryption_enc_values_supported)) {
        return false;
    }
    $is_gcm = false;
    if(strpos($enc, 'GCM') !== false) {
        $is_gcm = true;
    }
    
    
    $input_data = is_array($data) ? json_encode($data) : $data;
    if($zip)
        $input_data = gzdeflate($input_data);
    
    $key_strength = 0;
    $key_length = 0;
    if(!$enc) {
        $enc = 'A256CBC-HS512';
    }
    $int_key_strength = 512;
    switch($enc) {
        case 'A256CBC-HS512':
            $key_length = 64;
            $int_key_strength = 512;
            $key_strength = 256;
            break;
        case 'A256GCM':
            $key_length = 32;
            $key_strength = 256;
            break;
        case 'A128CBC-HS256':
            $key_length = 32;
            $int_key_strength = 256;
            $key_strength = 128;
            break;
        case 'A128GCM':
            $key_length = 16;
            $key_strength = 128;
            break;
        default:
            return false;
    }
    if($key_strength && $key_length) {
        if($enc_key)
            $cmk=$enc_key;
        else
            $cmk = random_bytes($key_length);
        $iv = random_bytes(16);
        $encoded_enc_key = base64url_encode(encrypt_with_key($cmk, $key_file, $is_private_key, $pass_phrase, $alg));

        $header = array (
                            'alg' => $alg,
                            'enc' => $enc
                        );
        if($zip)
            $header['zip'] = 'DEF';
        if($params) {
            $keys = array('jku', 'x5u', 'x5c', 'jwk', 'x5t', 'kid', 'cty', 'typ', 'crit', 'x5t#sha256');
            foreach ($keys as $key) {
                if(isset($params[$key])) {
                    $header[$key] = $params[$key];
                }
            }
        }
        if($iv)
            $encoded_iv =  base64url_encode($iv);
        $encoded_header = base64url_encode(json_encode($header));

        $cek = NULL;
        $cik = NULL;
        if($is_gcm) {
            $K = $cmk;
            $P = $input_data;
            $IV = $iv;
            $A = "{$encoded_header}";
            $t = 128;

            list($C, $T) = gcm_encrypt($K, $IV, $P, $A, $t);
            if(!$C)
                return false;
            $enc_data = base64url_encode($C);
            $integrity_hash = base64url_encode($T);
        } else {
            $cik = substr($cmk, 0, $key_length / 2);
            $cek = substr($cmk, $key_length / 2);
            $A = "{$encoded_header}";
            $al = pack('NN', 0, strlen($A) * 8);
            $encrypted_data = aes_cbc_encrypt($input_data, $cek, $key_strength, $iv);
            $enc_data = base64url_encode($encrypted_data);
            $integrity_hash = base64url_encode(substr(hash_hmac('sha' . $int_key_strength, "{$A}{$iv}{$encrypted_data}{$al}", $cik, true), 0, $key_length / 2));
        }

    }
    return sprintf('%s.%s.%s.%s.%s', $encoded_header, $encoded_enc_key, $encoded_iv, $enc_data, $integrity_hash);;                     
}

function jwt_encrypt($data, $key_file, $is_private_key=false, $pass_phrase=NULL, $public_cert_url=NULL, $enc_key=NULL, $alg='RSA1_5', $enc='A256CBC-HS512', $zip = true) {
    $header = NULL;
    if($public_cert_url)
        $header = array('jku' => $public_cert_url);
    return jwt_encrypt2($data, $key_file, $is_private_key, $pass_phrase, $header, $enc_key, $alg, $enc, $zip);
}

function jwt_decrypt($jwe, $key_file, $is_private_key=true, $pass_phrase=NULL, $allowed_algs=NULL, $allowed_encs=NULL) {
    global $encryption_alg_values_supported, $encryption_enc_values_supported;

    $parts = explode('.', $jwe);
    $rsa = null;
    if(count($parts) != 5) {
        return false;
    }
    $obj = array_map('base64url_decode', $parts);

    if(is_array($key_file)) {
        $rsa = new \phpseclib\Crypt\RSA();
        if($rsa) {
            $rsa->modulus = new phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($key_file['n'])), 16);
            $rsa->exponent = new phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($key_file['d'])), 16);
            $rsa->publicExponent = new phpseclib\Math\BigInteger('0x' . bin2hex(base64url_decode($key_file['e'])), 16);
            $rsa->k = strlen($rsa->modulus->toBytes());
            $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::SIGNATURE_PKCS1);
        }
    }
    elseif(is_string($key_file) && is_file($key_file)) {
        if(!file_exists($key_file)) {
            return false;
        }
    }
    $header = json_decode($obj[0], true);
    $encrypted_cek = $obj[1];
    $iv = $obj[2];
    $encrypted_payload = $obj[3];
    $integrity = $obj[4];
    if(!isset($header['enc']) || !isset($header['alg']))
        return false;
    if(!in_array($header['enc'], $encryption_enc_values_supported))
        return false;
    $is_gcm = false;
    if(strpos($header['enc'], 'GCM') !== false) {
        $is_gcm = true;
    }
    if(!in_array($header['alg'], $encryption_alg_values_supported))
        return false;
    if(!empty($allowed_algs)) {
        if(!is_array($allowed_algs))
            $allowed_algs = array($allowed_algs);
        if(!in_array($header['alg'], $allowed_algs))
            return false;
    }
    if(!empty($allowed_encs)) {
        if(!is_array($allowed_encs))
            $allowed_encs = array($allowed_encs);
        if(!in_array($header['enc'], $allowed_encs))
            return false;
    }
    if($rsa) {
        if($header['alg'] == 'RSA-OAEP') {
            $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
            $rsa->setHash('sha1');
            $rsa->setMGFHash('sha1');
        }
        $key = $rsa->decrypt($encrypted_cek);

    } else
        $key = decrypt_with_key($encrypted_cek, $key_file, $is_private_key, $pass_phrase, $header['alg']);
    if(!$key) {
        return false;
    }

    $int_key_strength = 512;
    switch($header['enc']) {
        case 'A256CBC-HS512':
            $key_length = 64;
            $key_strength = 256;
            $int_key_strength = 512;
            break;
        case 'A256GCM':
            $key_length = 32;
            $key_strength = 256;
            break;
        case 'A128CBC-HS256':
            $key_length = 32;
            $key_strength = 128;
            $int_key_strength = 256;
            break;
        case 'A128GCM':
            $key_length = 16;
            $key_strength = 128;
            break;
        default:
            return false;
    }
    
    if($is_gcm) {
        $K = $key;
        $IV = $iv;
        $C = $encrypted_payload;
        $A = "{$parts[0]}";
        $T = $integrity;
        
        list($plainText, $result) = gcm_decrypt($K, $IV, $C, $A, $T);
        if(!$plainText)
            return false;
    } else {
        if(strlen($key) != $key_length) {
            return false;
        }
        $cik = substr($key, 0, $key_length / 2);
        $cek = substr($key, $key_length / 2);

        switch($header['enc']) {
            case 'A256CBC-HS512':
                $plainText = aes_256_cbc_decrypt($encrypted_payload, $cek, $iv);
                break;
                
            case 'A128CBC-HS256':
                $plainText = aes_128_cbc_decrypt($encrypted_payload, $cek, $iv);
                break;
                
            case 'ECDH-ES':
            default:
                return false;
        }
        $A = "{$parts[0]}";
        $al = pack('NN', 0, strlen($A) * 8);
        $payload_integrity = substr(hash_hmac('sha' . $int_key_strength, "{$A}{$iv}{$encrypted_payload}{$al}", $cik, true), 0, $key_length / 2);
        if(strcmp($integrity, $payload_integrity)) {
            $msg = sprintf("int mismatched\ngot      %s\nexpected %s\nplain %s\n", bin2hex($integrity), bin2hex($payload_integrity), bin2hex($plainText));
            return false;
        }

    }
    if(isset($header['zip']) && $header['zip'] == 'DEF')
        $plainText = gzinflate($plainText);
    
    return $plainText;
}

if(!function_exists('gzdecode')) {

/**
 * Decodes a gzip compressed string
 * @param  String    $data         Data to decode
 * @return String                      DER encoded certificate
 */

function gzdecode($data,&$filename='',&$error='',$maxlength=null)
{
    $len = strlen($data);
    if ($len < 18 || strcmp(substr($data,0,2),"\x1f\x8b")) {
        $error = "Not in GZIP format.";
        return null;  // Not GZIP format (See RFC 1952)
    }
    $method = ord(substr($data,2,1));  // Compression method
    $flags  = ord(substr($data,3,1));  // Flags
    if ($flags & 31 != $flags) {
        $error = "Reserved bits not allowed.";
        return null;
    }
    // NOTE: $mtime may be negative (PHP integer limitations)
    $mtime = unpack("V", substr($data,4,4));
    $mtime = $mtime[1];
    $xfl   = substr($data,8,1);
    $os    = substr($data,8,1);
    $headerlen = 10;
    $extralen  = 0;
    $extra     = "";
    if ($flags & 4) {
        // 2-byte length prefixed EXTRA data in header
        if ($len - $headerlen - 2 < 8) {
            return false;  // invalid
        }
        $extralen = unpack("v",substr($data,8,2));
        $extralen = $extralen[1];
        if ($len - $headerlen - 2 - $extralen < 8) {
            return false;  // invalid
        }
        $extra = substr($data,10,$extralen);
        $headerlen += 2 + $extralen;
    }
    $filenamelen = 0;
    $filename = "";
    if ($flags & 8) {
        // C-style string
        if ($len - $headerlen - 1 < 8) {
            return false; // invalid
        }
        $filenamelen = strpos(substr($data,$headerlen),chr(0));
        if ($filenamelen === false || $len - $headerlen - $filenamelen - 1 < 8) {
            return false; // invalid
        }
        $filename = substr($data,$headerlen,$filenamelen);
        $headerlen += $filenamelen + 1;
    }
    $commentlen = 0;
    $comment = "";
    if ($flags & 16) {
        // C-style string COMMENT data in header
        if ($len - $headerlen - 1 < 8) {
            return false;    // invalid
        }
        $commentlen = strpos(substr($data,$headerlen),chr(0));
        if ($commentlen === false || $len - $headerlen - $commentlen - 1 < 8) {
            return false;    // Invalid header format
        }
        $comment = substr($data,$headerlen,$commentlen);
        $headerlen += $commentlen + 1;
    }
    $headercrc = "";
    if ($flags & 2) {
        // 2-bytes (lowest order) of CRC32 on header present
        if ($len - $headerlen - 2 < 8) {
            return false;    // invalid
        }
        $calccrc = crc32(substr($data,0,$headerlen)) & 0xffff;
        $headercrc = unpack("v", substr($data,$headerlen,2));
        $headercrc = $headercrc[1];
        if ($headercrc != $calccrc) {
            $error = "Header checksum failed.";
            return false;    // Bad header CRC
        }
        $headerlen += 2;
    }
    // GZIP FOOTER
    $datacrc = unpack("V",substr($data,-8,4));
    $datacrc = sprintf('%u',$datacrc[1] & 0xFFFFFFFF);
    $isize = unpack("V",substr($data,-4));
    $isize = $isize[1];
    // decompression:
    $bodylen = $len-$headerlen-8;
    if ($bodylen < 1) {
        // IMPLEMENTATION BUG!
        return null;
    }
    $body = substr($data,$headerlen,$bodylen);
    $data = "";
    if ($bodylen > 0) {
        switch ($method) {
        case 8:
            // Currently the only supported compression method:
            $data = gzinflate($body,$maxlength);
            break;
        default:
            $error = "Unknown compression method.";
            return false;
        }
    }  // zero-byte body content is allowed
    // Verifiy CRC32
    $crc   = sprintf("%u",crc32($data));
    $crcOK = $crc == $datacrc;
    $lenOK = $isize == strlen($data);
    if (!$lenOK || !$crcOK) {
        $error = ( $lenOK ? '' : 'Length check FAILED. ') . ( $crcOK ? '' : 'Checksum FAILED.');
        return false;
    }
    return $data;
}

}

/**
 * Converts a PEM encoded certificate to DER encoding
 * @param  String    $pem_data         PEM encoded certificate
 * @return String                      DER encoded certificate
 */
function pem2der($pem_data) {
   $begin = "CERTIFICATE-----";
   $end   = "-----END";
   $pem_data = substr($pem_data, strpos($pem_data, $begin)+strlen($begin));   
   $pem_data = substr($pem_data, 0, strpos($pem_data, $end));
   $der = base64_decode($pem_data);
   return $der;
}


/**
 * Converts a DER encoded certificate to PEM encoding
 * @param  String    $der_data         DER encoded certificate
 * @return String                      PEM encoded certificate
 */

function der2pem($der_data) {
   $pem = chunk_split(base64_encode($der_data), 64, "\n");
   $pem = "-----BEGIN CERTIFICATE-----\n".$pem."-----END CERTIFICATE-----\n";
   return $pem;
}



/**
 * Creates a RSA signture for data with a private key
 * @param  String    $data         Data to be signed
 * @param  resource  $key          Resource for OpenSSL private key
 * @param  String    $signature    parameter to receive the signature string
 * @param  String    $alg          Signature Algorithm(sha1, sha256, md5)
 * @return Bool                    Status of signing
 */

function digest_sign_data($data, $key, &$signature, $alg='sha256') {
/*

      MD2:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04
                   10 || H.
      MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04
                   10 || H.
      SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
      SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
                   04 20 || H.
      SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00
                   04 30 || H.
      SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00
                      04 40 || H.

*/

    $sha1_header = pack('H*', '3021300906052b0e03021a05000414');
    $sha256_header = pack('H*', '3031300d060960864801650304020105000420');
    $sha384_header = pack('H*', '3041300d060960864801650304020205000430');
    $sha512_header = pack('H*', '3051300d060960864801650304020305000440');
    $md2_header = pack('H*', '3020300c06082a864886f70d020205000410');
    $md5_header = pack('H*', '3020300c06082a864886f70d020505000410');
    $hash = hash($alg, $data, true);
    $sign_data = ${$alg . '_header'};
    if(!$sign_data)
        return false;
    $sign_data .= $hash;

    $cipherText = NULL;
    $status = openssl_private_encrypt($sign_data, $cipherText, $key);
    if(!$status) {
        return false;
    }
    $signature = $cipherText;
    return true;
}


/**
 * Verifies the RSA signature for data with a public key
 * @param  String    $data         Data for the signature
 * @param  String    $signature    Signature
 * @param  Resource  $key          Resource for OpenSSL public key
 * @param  String    $alg          Signature Algorithm(sha1, sha256, md5)
 * @return Bool                 Status of signature verification
 */

function digest_verify_data($data, $signature, $key, $alg='sha256') {
    $sha1_header = pack('H*', '3021300906052b0e03021a05000414');
    $sha256_header = pack('H*', '3031300d060960864801650304020105000420');
    $sha384_header = pack('H*', '3041300d060960864801650304020205000430');
    $sha512_header = pack('H*', '3051300d060960864801650304020305000440');
    $md2_header = pack('H*', '3020300c06082a864886f70d020205000410');
    $md5_header = pack('H*', '3020300c06082a864886f70d020505000410');
    
    $plainText = NULL;
    $status = openssl_public_decrypt($signature, $plainText, $key);
    if(!$status) {
        return false;
    }
    
    $hash = hash($alg, $data, true);
    $sign_data = ${$alg . '_header'};
    if(!$sign_data) {
        return false;
    }
    $sign_data .= $hash;
    if($sign_data == $plainText) {
        return true;
    }
    else {
        return false;
    }
}


function jwt_to_array($jwt) {
    $json_obj = NULL;
    if(is_string($jwt)) {
        if($jwt[0] == '{') { // use { as indicator of json encoded string - JSON serialization
            $json_obj = json_decode($jwt, true);
        }
        else {  // assumes that it's jwt compact serialization
            $jws_pattern = '/^(.+)\.(.+)\.(.*)$/';
            $jwe_pattern = '/^(.+)\.(.+)\.(.*)\.(.*)\.(.*)$/';
            if(preg_match($jwe_pattern, $jwt, $matches, PREG_OFFSET_CAPTURE)) {
                $json_obj = Array();
                $json_obj[0] = json_decode(base64url_decode($matches[1][0]), true);
                $json_obj[1] = json_decode(base64url_decode($matches[2][0]), true);
                $json_obj[2] = json_decode(base64url_decode($matches[3][0]), true);
                $json_obj[3] = json_decode(base64url_decode($matches[4][0]), true);
                $json_obj[4] = json_decode(base64url_decode($matches[5][0]), true);
            } elseif(preg_match($jws_pattern, $jwt, $matches, PREG_OFFSET_CAPTURE)) {
                $json_obj = Array();
                $json_obj[0] = json_decode(base64url_decode($matches[1][0]), true);
                $json_obj[1] = json_decode(base64url_decode($matches[2][0]), true);
                $json_obj[2] = base64url_decode($matches[3][0]);
            }
        }
    }
    return $json_obj;
}

function kdfImpl($key_data_len, $alg, $master_key, $other_info) {
    $algs = array( 
                    'sha1' => 160,
                    'sha256' => 256,
                    'sha384' => 384,
                    'sha512' => 512,
                    'md5' => 128
                  );
    $max_hash_input_len = 1024;
    
    if(!$key_data_len || !isset($master_key) || !isset($algs[$alg]))
        return false;
    $hash_len = $algs[$alg];
    $reps = (int) ceil((float)($key_data_len / $hash_len));
    if($reps > (pow(2, 32) - 1) )
        return false;

    $counter = 0x0001;    
    if(strlen(pack('N', $counter) . $master_key . $other_info) * 8 > $max_hash_input_len)
        return false;
    $hashes = array();

    for($counter = 1; $counter <= (int) $reps; $counter++) {
        $input = pack('N', $counter) . $master_key . $other_info;
        $hash = hash($alg, $input, true);
        if($counter == $reps) {
            $remainder = $key_data_len % $hash_len;
            if($remainder) {
                if($remainder % 8)
                    return false; // cannot deal with non byte size remainders
                $num_bytes = $remainder / 8;
                $hash = substr($hash, 0, $num_bytes);
            }
        }
        array_push($hashes, $hash);
    }
    $fullhash = '';
    foreach($hashes as $h) {
        $fullhash .= $h;
    }
    return $fullhash;
    
}


function make_kdf_other_info($algID, $partyu, $partyv, $supp_pub, $supp_priv) {
    return $algID . pack('N', strlen($partyu)) . $partyu . pack('N', strlen($partyv)).  $partyv . $supp_pub . $supp_priv;
}

function jweKDF($key_data_len, $master_key, $enc, $partyu, $partyv, $label) {
    $alg = 'sha256';
    switch($enc) {
        case 'A128CBC-HS256' :
            $alg = 'sha256';
        break;
        
        case 'A256CBC-HS512' :
            $alg = 'sha512';
        break;
        
        default :
        return NULL;
    }
    $alg_id = pack('N', $key_data_len) . $enc;
    $other_info = make_kdf_other_info($alg_id, $partyu, $partyv, $label, '');
    return kdfImpl($key_data_len, $alg, $master_key, $other_info);
}

function kdf($key_data_len, $alg, $master_key, $label) {
    $algs = array( 
                    'sha1' => 160,
                    'sha256' => 256,
                    'sha384' => 384,
                    'sha512' => 512,
                    'md5' => 128
                  );
    $max_hash_input_len = 1024;
    
    if(!$key_data_len || !isset($master_key) || !isset($algs[$alg]))
        return false;
    $hash_len = $algs[$alg];
    $reps = (int) ceil((float)($key_data_len / $hash_len));
    if($reps > (pow(2, 32) - 1) )
        return false;

    $counter = 0x0001;    
    if(strlen(pack('N', $counter) . $master_key . $label) * 8 > $max_hash_input_len)
        return false;
    $hashes = array();

    for($counter = 1; $counter <= (int) $reps; $counter++) {
        $input = pack('N', $counter) . $master_key . $label;
        $hash = hash($alg, $input, true);
        if($counter == $reps) {
            $remainder = $key_data_len % $hash_len;
            if($remainder) {
                if($remainder % 8)
                    return false; // cannot deal with non byte size remainders
                $num_bytes = $remainder / 8;
                $hash = substr($hash, 0, $num_bytes);
            }
        }
        array_push($hashes, $hash);
    }
    $fullhash = '';
    foreach($hashes as $h) {
        $fullhash .= $h;
    }
    return $fullhash;
}

function bitxor($o1, $o2) {
     $xorWidth = PHP_INT_SIZE;
     $o1 = str_split($o1, $xorWidth);
     $o2 = str_split($o2, $xorWidth);
     $res = '';
     $runs = count($o1);
     for($i=0;$i<$runs;$i++)
         $res .= $o1[$i] ^ $o2[$i];        
    return $res;
}


function aes_key_wrap($input, $KEK) {
    $input_len = strlen($input);
    $key_length = strlen($KEK) * 8;
    $method = '';
    if($key_length != 128 && $key_length != 192 && $key_length != 256) {
        die("aes_key_wrap invalid key length {$key_length}\n");
    } else {
        $method = 'aes-' . $key_length . '-ecb';
    }

    if($key_length < $input_len * 8) {
        die("aes_key_wrap insufficient key length for input\n");
    }

    $n = (int) ceil(($input_len * 8) / 64);
    $iv = pack('H*', 'A6A6A6A6A6A6A6A6');

    $A = $iv;
    $R = array();

    for($i = 1; $i <= $n; $i++) {
        $R[$i] = substr($input, ($i - 1) * 8, 8);
        if(strlen($R[$i]) < 8) {
            $R[$i] = str_pad($R[$i], 8 - strlen($R[$i]), "\0");
        }
    }

    for($j = 0; $j < 6; $j++) {
        for($i = 1; $i <= $n; $i++) {
            $B = openssl_encrypt($A . $R[$i], $method, $KEK, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            $R[$i] = substr($B, -8);
            $A = substr($B, 0, 8);
            $t1 = ($n * $j) + $i;
            $t = pack('N', $t1);
            $padded_t = str_pad($t, 8, "\0", STR_PAD_LEFT);
            $A = bitxor($A, $padded_t);
        }
    }

    $C = array();
    $C[0] = $A;
    for($i = 1; $i <= $n; $i++) {
        $C[$i] = $R[$i];
    }
    return implode('', $C);

}

function aes_key_unwrap($input, $KEK) {
    $input_len = strlen($input);
    $key_length = strlen($KEK) * 8;
    $method = '';
    if($key_length != 128 && $key_length != 192 && $key_length != 256) {
        die("aes_key_unwrap invalid key length {$key_length}\n");
    } else {
        $method = 'aes-' . $key_length . '-ecb';
    }
    $n = ceil(($input_len * 8) / 64) - 1;
    if($key_length < ($n) * 8) {
        die("aes_key_unwrap insufficient key length for input\n");
    }
    $A = substr($input, 0, 8);
    $R = array();

    for($i = 1; $i <= $n; $i++) {
        $R[$i] = substr($input, $i * 8, 8);
        if(strlen($R[$i]) < 8) {
            $R[$i] = str_pad($R[$i], 8 - strlen($R[$i]), "\0");
        }
    }
    for($j = 5; $j >= 0; $j--) {
        for($i = $n; $i >= 1; $i--) {
            $t1 = ($n * $j) + $i;
            $t = pack('N', $t1);
            $padded_t = str_pad($t, 8, "\0", STR_PAD_LEFT);
            $A = bitxor($A, $padded_t);
            $B = openssl_decrypt($A . $R[$i], $method, $KEK, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            $A = substr($B, 0, 8);
            $R[$i] = substr($B, -8);
        }
    }

    $P = array();
    $P[0] = $A;
    for($i = 1; $i <= $n; $i++) {
        $P[$i] = $R[$i];
    }
    $P0 = pack('H*', 'A6A6A6A6A6A6A6A6');
    if(strcmp($P0, $P[0]) == 0) {
        unset($P[0]);
        return implode('', $P);
    } else
        return NULL;
}


function add_pkcs5_padding($input, $block_len = 16) {
    $last_block_len = strlen($input) % $block_len;
    $pad_len = $block_len - ($last_block_len % $block_len);
    return $input . str_pad('', $pad_len, pack('H*', sprintf("%02x", $pad_len)));
}

function remove_pkcs5_padding($input) {
    return substr($input, 0, strlen($input) - ord(substr($input, -1)));
}


/*
 *
 * GCM Crypto Functions
 *
 */
function gcm_encrypt($K, $IV, $P, $A, $t = 128) {

    $key_length = strlen($K) * 8;
    $method = '';
    if($key_length != 128 && $key_length != 192 && $key_length != 256) {
        die("gcm encryp invalid key length {$key_length}\n");
    } else {
        $method = 'aes-' . $key_length . '-gcm';
    }

    $tagLength = $t / 8;
    $T = NULL;
    $cipherText = openssl_encrypt($P, $method, $K, OPENSSL_RAW_DATA, $IV, $T, $A, $tagLength);
    if($cipherText) {
        return array($cipherText, $T);
    } else
        return NULL;
}


function gcm_decrypt($K, $IV, $C, $A, $T) {
    $key_length = strlen($K) * 8;
    $method = '';
    if($key_length != 128 && $key_length != 192 && $key_length != 256) {
        die("gcm decryp invalid key length {$key_length}\n");
    } else {
        $method = 'aes-' . $key_length . '-gcm';
    }
    $clearText = openssl_decrypt($C, $method, $K, OPENSSL_RAW_DATA, $IV, $T, $A);
    if(!$clearText)
        return NULL;
    return array($clearText, 0);
}


function pretty_json($json) {

    $result = '';
    $pos = 0;
    $strLen = strlen($json);
    $indentStr = ' ';
    $newLine = "\n";
    $prevChar = '';
    $outOfQuotes = true;

    for ($i=0; $i<=$strLen; $i++) {

        // Grab the next character in the string.
        $char = substr($json, $i, 1);

        // Are we inside a quoted string?
        if ($char == '"' && $prevChar != '\\') {
            $outOfQuotes = !$outOfQuotes;

            // If this character is the end of an element,
            // output a new line and indent the next line.
        } else if(($char == '}' || $char == ']') && $outOfQuotes) {
            $result .= $newLine;
            $pos --;
            for ($j=0; $j<$pos; $j++) {
                $result .= $indentStr;
            }
        }

        // Add the character to the result string.
        $result .= $char;

        // If the last character was the beginning of an element,
        // output a new line and indent the next line.
        if (($char == ',' || $char == '{' || $char == '[') && $outOfQuotes) {
            $result .= $newLine;
            if ($char == '{' || $char == '[') {
                $pos ++;
            }

            for ($j = 0; $j < $pos; $j++) {
                $result .= $indentStr;
            }
        }

        $prevChar = $char;
    }

    return $result;
}

function get_mod_exp_from_key($key_contents, $pass_phrase = NULL, $is_private_key = false) {

    if($is_private_key)
        $key = openssl_pkey_get_private($key_contents, $pass_phrase);
    else
        $key = openssl_pkey_get_public($key_contents);

    $rsa = new \phpseclib\Crypt\RSA();
    if($rsa) {
        if($is_private_key) {
            $rsa->setPassword($pass_phrase);
            if(!$rsa->loadkey($key_contents, \phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1)) {
                return NULL;
            }
        }
        else {
            $details = openssl_pkey_get_details($key);
            $pubkey = $details['key'];
            if(!$rsa->loadkey($pubkey, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1))
                return NULL;
        }
        return array($rsa->modulus->toBytes(), $is_private_key ? $rsa->publicExponent->toBytes() : $rsa->exponent->toBytes());
    }
    return NULL;
}

function get_rsa_jwk_thumbprint($n, $e) {
    if(!$n || !$e)
        return '';
    $key_info =  array(  'e'   => base64url_encode($e),
        'kty' => 'RSA',
        'n'   => base64url_encode($n),
    );
    return base64url_encode(hash('sha256', json_encode($key_info), true));
}

function get_rsa_key_thumbprint($key) {
    if($key) {
        $key_pattern = '/(?m)^-----BEGIN (CERTIFICATE|PUBLIC KEY|RSA PRIVATE KEY)-----$\n((?s).*)\n^-----END (CERTIFICATE|PUBLIC KEY|RSA PRIVATE KEY)-----$/';  // matches whole block,
        if(preg_match($key_pattern, $key, $matches)) {
            if($matches[1] == 'RSA PRIVATE KEY')
                $pubinfo = get_mod_exp_from_key($key, NULL, true);
            else
                $pubinfo = get_mod_exp_from_key($key);

            if($pubinfo) {
                list($n, $e) = $pubinfo;
                if($n && $e) {
                    return get_rsa_jwk_thumbprint($n, $e);
                }
            }
        }
    }
    return '';
}



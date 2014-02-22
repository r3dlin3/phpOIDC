<?php
include_once('base64url.php');
include_once('libjsoncrypto.php');

function test_jwk()
{
/*
    $n = base64url_encode(pack('H*', 'D02734CF2EA90B77E8544452D866DA4E6E9037F400FDB7BD8980FA1CD9CAA6BD938C8251FDDDE3A2CF6974F3A399FF87FFF00E33F8C67E0153102BAF590243F4EF7A6D81131DB396DC3B1D637EC013C21B7F51893FFF887423FE1FC9E36F02977A6F5607AC46DF3B3BD34E9F45EC8B0E2525E39BD06BF9655BABFE11477D590D'));
    $e = base64url_encode(pack('H*', '010001'));
*/

/*
    OpenID Specs Standard Example RP Keys
    $n = base64url_encode(pack('H*', 'CBD2EABF87C2A7A122FAEDBE6422AAF3762F6C5124E8932CFE94A3EFA78C91D75646E597D9A04A18702D2A51393FBFEF9FFFCF08A65678FB77BC6901E9E3E0CC016ED3C36629E9B01396D02347BA9080A1B6DFFA2B34F939A6970C523AA822C99A4E7509CE156056B182A7AF327718AF3696FF9D26675C86485210CCB60FF1B8A30071958DD10581969910DF65B27FC67562DA2691EB07744E952E74138E70C6B960F713277156FCA833EE5D96ABBE084B2F41F33AE61169D049568599A300CD4E92A9936464959ED06813BB5C3BF7B91EECFEC7F683E6C08D26316141ACAA4340F5BDF1556E776A6FD4659DED65B153221E79EC920258A1E55A3E6ECDE2576B'));
    $e = base64url_encode(pack('H*', '010001'));

*/

/*
    OpenID Specs Standard Example OP Keys
    $n = base64url_encode(pack('H*', 'CE11164C12554DF7147AA9CCCCE4053021154163B23946703FC2EB05687CF2D2AB6723C60AF0644C3A7E136073C87310578A4AE75532B3660EC332FDB1EE531C358C75AF6BB6C08955C8F557B59A13BC0F825FA420875659FE28DA0E99B333B2FC5A78AB49C6DCE4ED0D10A406EDA210FDB58FCDA945246B9020719F368285F940ECA65B2359FFCA12ADC7203B15D038F342DA495672280A6FACA898868700092C1FD32E8243EC24122EA6557449B756814B2C252D8034F288E9E61919437F5E08CDA4D447577616DAAFDF7C43D3D94F05C0D5C7EFB864D96C35B110A2E330A56E2AB4F562FB3ED8D4D7859016D4A8C54BFDD4C0B90393EC3875537EC79B439F'));
    $e = base64url_encode(pack('H*', '010001'));

*/
    $n = base64url_encode(pack('H*', 'BC880BCBE3D6DA8422F02FA433107E0A2CC35DCBA414BD67696C326B9A2C33498CDFC52886FE1D5476AAD323EC0602D3EC182611B12694D7253551443CFECCB37BBAB79D371BA1563EFABE6535B5FBC43745EAD88358A16789DDDF5F66D90180A97B1277E4833F39F032C07D9B89CC3C9C3B3B995D1E6BDBDCD7303B2D4F9179'));
    $e = base64url_encode(pack('H*', '010001'));

/*
$jwk = <<<EOF
{"keys":[{"use":"sig","kty":"RSA","n":"$n","e":"$e","kid":"op-key1"}]}
EOF;
*/

$jwk = <<<EOF
{"keys":[
          {
           "kty":"RSA",
           "n":"$n",
           "e":"$e"
          }
        ]
}
EOF;


    echo $jwk . "\n";    
    
    
//    $rsa = new Crypt_RSA();
//    print_r($rsa);
//    
//    $rsa->loadKey(file_get_contents('/home/edmund/test/ca/nat_ab/abop/testkeys/2048Key.pub'));
//    
//    printf($rsa->modulus->toHex());
//    printf($rsa->exponent->toHex());    
    
    
}

/**
Parameters

    $n  modulus in big endian format
    $e  exponent in big endian format
    $kid kid string
    $use key usage: sig or enc

**/

function make_rsa_jwk($n, $e, $kid = NULL, $use = '') {
    
    if(!$n || !$e)
        return false;
        
    $key_info =  array( 'kty' => 'RSA',
                         'n'   => base64url_encode($n),
                         'e'   => base64url_encode($e)
                      );
    if($kid)
        $key_info['kid'] = $kid;
    if($use)
        $key_info['use'] = $use;                      
 
    $jwk = array('keys' => array($key_info));
    return pretty_json(json_encode($jwk));
    
}


function make_rsa_jwk_key($n, $e, $kid = NULL, $use = '') {
    
    if(!$n || !$e)
        return false;
        
    $key_info =  array( 'kty' => 'RSA',
                         'n'   => base64url_encode($n),
                         'e'   => base64url_encode($e)
                      );
    if($kid)
        $key_info['kid'] = $kid;
    if($use)
        $key_info['use'] = $use;                      
    return $key_info; 
}

function make_rsa_pkix_key($cert_chain, $kid = NULL, $use = '') {
    
    if(!$cert_chain)
        return false;
        
    $key_info =  array( 'kty' => 'PKIX',
                         'x5c'   => $cert_chain
                      );
    if($kid)
        $key_info['kid'] = $kid;
    if($use)
        $key_info['use'] = $use;                      
    return $key_info; 
}


function make_jwk($keys) {
    if(!is_array($keys))
        $keys = array($keys);
    $jwk = array('keys' => $keys);
    return pretty_json(json_encode($jwk));
}


function get_mod_exp_from_key($key_contents, $passord = NULL, $is_private_key = false) {

    if($is_private_key)
        $key = openssl_pkey_get_private($key_contents, $pass_phrase);
    else 
        $key = openssl_pkey_get_public($key_contents);
        

    $rsa = new Crypt_RSA();
    if($rsa) {
        if($is_private_key) {
            $rsa->setPassword($passord);
            if(!$rsa->loadkey($key_contents, CRYPT_RSA_PRIVATE_FORMAT_PKCS1))
                return false;
        }
        else {
            $details = openssl_pkey_get_details($key);
            $pubkey = $details['key'];
            if(!$rsa->loadkey($pubkey, CRYPT_RSA_PUBLIC_FORMAT_PKCS1))
                return false;
        }
        return array($rsa->modulus->toBytes(), $is_private_key ? $rsa->publicExponent->toBytes() : $rsa->exponent->toBytes());
    }
    return NULL;
}

function test_make_jwk() {

$cert = <<<EOF
-----BEGIN CERTIFICATE-----
MIIDKDCCAhACCQDSuHJ7GyIxcjANBgkqhkiG9w0BAQUFADBWMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIE1hdGVvMQwwCgYD
VQQKEwNOUkkxEDAOBgNVBAMTBzIwNDhLZXkwHhcNMTEwMzMwMjIzOTUzWhcNMTIw
MzI5MjIzOTUzWjBWMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTES
MBAGA1UEBxMJU2FuIE1hdGVvMQwwCgYDVQQKEwNOUkkxEDAOBgNVBAMTBzIwNDhL
ZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOERZMElVN9xR6qczM
5AUwIRVBY7I5RnA/wusFaHzy0qtnI8YK8GRMOn4TYHPIcxBXikrnVTKzZg7DMv2x
7lMcNYx1r2u2wIlVyPVXtZoTvA+CX6Qgh1ZZ/ijaDpmzM7L8WnirScbc5O0NEKQG
7aIQ/bWPzalFJGuQIHGfNoKF+UDsplsjWf/KEq3HIDsV0DjzQtpJVnIoCm+sqJiG
hwAJLB/TLoJD7CQSLqZVdEm3VoFLLCUtgDTyiOnmGRlDf14IzaTUR1d2Ftqv33xD
09lPBcDVx++4ZNlsNbEQouMwpW4qtPVi+z7Y1NeFkBbUqMVL/dTAuQOT7Dh1U37H
m0OfAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKERW9CNq9YxKZHD/VeBwFC8AyEB
NkbQR1GslmKaV1i2vUa6lOMrtjP23KVCe8LA2LFE+AqA68EmWEqXd/Rs1ODSDIhQ
CsVaJF2BG/qvGa55ipUQF+KvuqgoNp2mPB3mVVjd2HRFytIjmAKBuKWngc7jxPw9
jzb+hcBChSfEQS5AM9Mjsz4D7M/KcOsW9xzOxyRaR1VGVvHHUPckLyq2QDRp4Kf3
jEAjExoLtgwzEXw6xvilKAPPqHA2lw9lOYljXObGDQKkJlNYS+t8+oJCCk6vEV0O
Vq8aYgGTOYcXEpRQDc5/iB9AeGSyFN0+BcqLXKE4W9M+CwYOiG3pnulR8yY=
-----END CERTIFICATE-----
EOF;
$private_key = <<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzhEWTBJVTfcUeqnMzOQFMCEVQWOyOUZwP8LrBWh88tKrZyPG
CvBkTDp+E2BzyHMQV4pK51Uys2YOwzL9se5THDWMda9rtsCJVcj1V7WaE7wPgl+k
IIdWWf4o2g6ZszOy/Fp4q0nG3OTtDRCkBu2iEP21j82pRSRrkCBxnzaChflA7KZb
I1n/yhKtxyA7FdA480LaSVZyKApvrKiYhocACSwf0y6CQ+wkEi6mVXRJt1aBSywl
LYA08ojp5hkZQ39eCM2k1EdXdhbar998Q9PZTwXA1cfvuGTZbDWxEKLjMKVuKrT1
Yvs+2NTXhZAW1KjFS/3UwLkDk+w4dVN+x5tDnwIDAQABAoIBABjSKhNjqe7IMilM
RqTvWkif04Wa0p7fgynK+rAeE97TzV2RC4vJxOsBqKoA1jFw2qkQuVEADClbw69z
dud1w4EEWjTaumi67E/u8s5ry3FRF7UmfAiHBLm2SYlqdM0HDyoiY6KOMmvtDzih
poBHI1xUkwgNR7RSXLpxjf4VfMdSNTyQfW8rT83t9cqno1+8OmSBD+UwR6Fgb8a5
pywbgVv3rneFiyjSmglnXa6mMPK5T0hK4I0w33F2et91JUNAsYwVVPmLpW7EYMXu
oDV7U1Qn4DCQ1AlNqqFjjOZPvUDGJ8G9MbpMNXxbJEG+0hrpVlSGqrwfCqy2RIs6
XmGz+rECgYEA8liamKu5qze44S1UF9fTmKm8L2HX9pTsQllsyF93mU3JMtA6Uqur
dxmpOPB/jmxWp2x7F4wyDhsiWsy2AeILTEncc8eY4DLWZCG/RrUs6BkzIkzRwWeN
OBiw1tzR+vdCPGZBOnGIiWDk3X+TmV0baeVDBCUJ1Lx3HEtqyAc2lnMCgYEA2a04
YghNqv0ujAu1gDS5jq/DGoTm8dMRKvPYEAv96BQlKmT0v2BJZ2BhZSgfOkIKW6qa
ttiVipWSIjPIxHo7KWT0JAyYtM0E7+Wj/7hvyRRAWaPYZBR3xSjFUC+k8lNZtS0K
F3L5bcfS5leb+/OU1yhNfGUlEk+9tjiaPyYEJyUCgYAaPHtoIdc08RBj2FttRWFT
+rQz0PznZhH50OKVArjY8PHiPWbDAnDKsQ1/65Fzosjy0Sy2TOgyXL+oYtcldwpQ
FQL3ydkEFJzfNEQX7I9TBT9i7DwdGw/PzeR/LmLRL6mNDmjrYdUtQj8kt6YMCWdp
XHeX4EajMFAY0RVbWGSRfwKBgQC+Hz6E2U3FD/fM2BlCDksX5koZaoUwKDLxeiN3
+JFfV+ESQzVFxfq28QaATOfhgXb8k2koVMlgTr1hZCtx+HSd9hALQHlMSVmLkt6H
5va0AR0nbiT9XKczrCWSoNqH0OckiF8tFf3ntcVt7I1QJXMV7ZyoDsuvT7iaZJvM
lg7AhQKBgCMKCTtp6X/VhrmHoqpujwzHtfUGJ9ihhoTfVfKtUEnY7V7qXZPtD/ie
g6/wcEIlw5GHhWhwwWaFdQjI1TEmBx1KFAr2GjH0ByOajH23Q5gnbzGdMsYTVHqX
TG4hFjz818ildLk84z8SGoAhCPjcKe9ditAj/c+4DGXhOeE6LJrh
-----END RSA PRIVATE KEY-----
EOF;

    $pubinfo = get_mod_exp_from_key($cert);
    if($pubinfo) {
        list($n, $e) = $pubinfo;
        $jwk = make_rsa_jwk($n, $e);
        printf("%s\n", $jwk);
    }
    
    $pubinfo =  get_mod_exp_from_key($private_key, '', true);
    if($pubinfo) {
        list($n, $e) = $pubinfo;
        $jwk = make_rsa_jwk($n, $e);
        printf("%s\n", $jwk);
    }

    $rsa = new Crypt_RSA();
    $out = $rsa->createKey(2048);
    print_r($out);
    extract($out);
    $rsa->loadKey($publickey);
    print_r($privatekey);
    print_r($publickey);
    $jwk = make_rsa_jwk($rsa->modulus->toBytes(), $rsa->publicExponent ? $rsa->publicExponent->toBytes() : $rsa->exponent->toBytes());
    printf("%s\n", $jwk);
}

// test_jwk();

//printf("vI modulus = %s\n", bin2hex(base64url_decode('vIgLy-PW2oQi8C-kMxB-CizDXcukFL1naWwya5osM0mM38Uohv4dVHaq0yPsBgLT7BgmEbEmlNclNVFEPP7Ms3u6t503G6FWPvq-ZTW1-8Q3RerYg1ihZ4nd319m2QGAqXsSd-SDPznwMsB9m4nMPJw7O5ldHmvb3NcwOy1PkXk')));
//
//
//printf("AL modulus = %s\n", bin2hex(base64url_decode('ALyIC8vj1tqEIvAvpDMQfgosw13LpBS9Z2lsMmuaLDNJjN_FKIb-HVR2qtMj7AYC0-wYJhGxJpTXJTVRRDz-zLN7uredNxuhVj76vmU1tfvEN0Xq2INYoWeJ3d9fZtkBgKl7Enfkgz858DLAfZuJzDycOzuZXR5r29zXMDstT5F5')));


// exit;

//test_make_jwk();



//$cert1 = <<<EOF
//-----BEGIN CERTIFICATE-----
//MIIDKDCCAhACCQDSuHJ7GyIxcjANBgkqhkiG9w0BAQUFADBWMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIE1hdGVvMQwwCgYDVQQKEwNOUkkxEDAOBgNVBAMTBzIwNDhLZXkwHhcNMTEwMzMwMjIzOTUzWhcNMTIwMzI5MjIzOTUzWjBWMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIE1hdGVvMQwwCgYDVQQKEwNOUkkxEDAOBgNVBAMTBzIwNDhLZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOERZMElVN9xR6qczM5AUwIRVBY7I5RnA/wusFaHzy0qtnI8YK8GRMOn4TYHPIcxBXikrnVTKzZg7DMv2x7lMcNYx1r2u2wIlVyPVXtZoTvA+CX6Qgh1ZZ/ijaDpmzM7L8WnirScbc5O0NEKQG7aIQ/bWPzalFJGuQIHGfNoKF+UDsplsjWf/KEq3HIDsV0DjzQtpJVnIoCm+sqJiGhwAJLB/TLoJD7CQSLqZVdEm3VoFLLCUtgDTyiOnmGRlDf14IzaTUR1d2Ftqv33xD09lPBcDVx++4ZNlsNbEQouMwpW4qtPVi+z7Y1NeFkBbUqMVL/dTAuQOT7Dh1U37Hm0OfAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKERW9CNq9YxKZHD/VeBwFC8AyEBNkbQR1GslmKaV1i2vUa6lOMrtjP23KVCe8LA2LFE+AqA68EmWEqXd/Rs1ODSDIhQCsVaJF2BG/qvGa55ipUQF+KvuqgoNp2mPB3mVVjd2HRFytIjmAKBuKWngc7jxPw9jzb+hcBChSfEQS5AM9Mjsz4D7M/KcOsW9xzOxyRaR1VGVvHHUPckLyq2QDRp4Kf3jEAjExoLtgwzEXw6xvilKAPPqHA2lw9lOYljXObGDQKkJlNYS+t8+oJCCk6vEV0OVq8aYgGTOYcXEpRQDc5/iB9AeGSyFN0+BcqLXKE4W9M+CwYOiG3pnulR8yY=
//-----END CERTIFICATE-----
//EOF;
//
//
//$cert2 = <<<EOF
//-----BEGIN CERTIFICATE-----
//MIIDKDCCAhACCQDSuHJ7GyIxcjANBgkqhkiG9w0BAQUFADBWMQswCQYDVQQGEwJV
//UzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIE1hdGVvMQwwCgYD
//VQQKEwNOUkkxEDAOBgNVBAMTBzIwNDhLZXkwHhcNMTEwMzMwMjIzOTUzWhcNMTIw
//MzI5MjIzOTUzWjBWMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTES
//MBAGA1UEBxMJU2FuIE1hdGVvMQwwCgYDVQQKEwNOUkkxEDAOBgNVBAMTBzIwNDhL
//ZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOERZMElVN9xR6qczM
//5AUwIRVBY7I5RnA/wusFaHzy0qtnI8YK8GRMOn4TYHPIcxBXikrnVTKzZg7DMv2x
//7lMcNYx1r2u2wIlVyPVXtZoTvA+CX6Qgh1ZZ/ijaDpmzM7L8WnirScbc5O0NEKQG
//7aIQ/bWPzalFJGuQIHGfNoKF+UDsplsjWf/KEq3HIDsV0DjzQtpJVnIoCm+sqJiG
//hwAJLB/TLoJD7CQSLqZVdEm3VoFLLCUtgDTyiOnmGRlDf14IzaTUR1d2Ftqv33xD
//09lPBcDVx++4ZNlsNbEQouMwpW4qtPVi+z7Y1NeFkBbUqMVL/dTAuQOT7Dh1U37H
//m0OfAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKERW9CNq9YxKZHD/VeBwFC8AyEB
//NkbQR1GslmKaV1i2vUa6lOMrtjP23KVCe8LA2LFE+AqA68EmWEqXd/Rs1ODSDIhQ
//CsVaJF2BG/qvGa55ipUQF+KvuqgoNp2mPB3mVVjd2HRFytIjmAKBuKWngc7jxPw9
//jzb+hcBChSfEQS5AM9Mjsz4D7M/KcOsW9xzOxyRaR1VGVvHHUPckLyq2QDRp4Kf3
//jEAjExoLtgwzEXw6xvilKAPPqHA2lw9lOYljXObGDQKkJlNYS+t8+oJCCk6vEV0O
//Vq8aYgGTOYcXEpRQDc5/iB9AeGSyFN0+BcqLXKE4W9M+CwYOiG3pnulR8yY=
//-----END CERTIFICATE-----
//EOF;

//$key = openssl_pkey_get_public($cert1);
//if(!$key) {
//    echo "no key1\n";
//} else
//    echo "got key1\n";
//
//$key2 = openssl_pkey_get_public($cert2);
//if(!$key2) {
//    echo "no key2\n";
//} else
//    echo "got key2\n";


if($argc > 1) {
    $cert = file_get_contents($argv[1]);
    if($cert) {
        $pattern = '/(?m)^-----BEGIN CERTIFICATE-----$\n((?s).*)\n^-----END CERTIFICATE-----$/';  // matches whole block, 
//        $pattern = '/(?m)^-----BEGIN CERTIFICATE-----$\n((^.*$\n*)*)^-----END CERTIFICATE-----$/';  // matches individual lines
        if(preg_match($pattern, $cert, $matches)) {
//            print_r($matches);
            $encoded_der = $matches[1];
//            
//            $replace_pattern = '/[:space:]/';
//            $replacement = preg_replace('/\n/' , '', $encoded_der);
//            echo "replacement = $replacement\n";
            $jwk_keys = array();
            $pubinfo = get_mod_exp_from_key($cert);
            $kid = $argv[2];
            $use = $argv[3];
            
            if($pubinfo) {
                list($n, $e) = $pubinfo;
                $jwk_key = make_rsa_jwk_key($n, $e, $kid, $use);
                $jwk_key['x5c'] = array($encoded_der);
                if($jwk_key) 
                    $jwk_keys[] = $jwk_key;
            }
            
//            $pkix_key = make_rsa_pkix_key(array($encoded_der), $kid, $use);
//            if($pkix_key)
//                $jwk_keys[] = $pkix_key;
            $jwk = make_jwk($jwk_keys);
            printf("%s\n", $jwk);
            



//            print_r(explode("\n", $matches[1]));
        } else
            printf("no match\n");
//        list($n, $e) = $pubinfo;
//        $jwk = make_rsa_jwk($n, $e);
//        printf("%s\n", $jwk);
    }
} else {
    printf("Usage : php makejwk.php pem_file_path kid use\n");
}







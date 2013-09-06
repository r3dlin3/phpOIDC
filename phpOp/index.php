<?php
/**
 * op.php
 *
 * This is a sample implementation of OpenID/AB1.0 draft12 provider.
 * License: GPL v.3
 *
 * @author Nat Sakimura (http://www.sakimura.org/)
 * @version 0.6
 * @create 2010-06-12
 */

include_once("abconstants.php");
include_once("libjsoncrypto.php");
include_once("libmysqlcrypt.php");
include_once('libdb.php');
include_once('logging.php');

define("DEBUG",0);

define("OP_ENDPOINT", OP_URL . "/op.php");


define("TOKEN_TYPE_AUTH_CODE", 0);
define("TOKEN_TYPE_ACCESS",    1);
define("TOKEN_TYPE_REFRESH",   2);


header('Content-Type: text/html; charset=utf8');

$session_path = session_save_path() . '/abop';
if(!file_exists($session_path))
    mkdir($session_path);
session_save_path($session_path);




$path_info = NULL;
if(substr($_SERVER['PATH_INFO'], 0, 2) == '/1') {
    define("SERVER_ID", OP_URL );
    $path_info = substr($_SERVER['PATH_INFO'], 2);
}
else {
    define("SERVER_ID", OP_PROTOCOL . OP_SERVER_NAME . OP_PORT);
    $path_info = $_SERVER['PATH_INFO'];
}

switch($path_info) {
    case '/token':
    case '/userinfo':
    case '/distributedinfo':
    case '/check_id':
    case '/registration':
    case '/sessioninfo':
    case '/client':    
    break;
    
    default:
        session_start();
        break;
    
}


logw_debug("Request: %s\nInput: %s\nSession:%s", count($_REQUEST) ? print_r($_REQUEST, true) : 'req[ ]', file_get_contents('php://input'), isset($_SESSION) ? print_r($_SESSION, true) : 'sess[ ]');


if($path_info == '/auth')
    handle_auth();
elseif($path_info == '/token')
    handle_token();
elseif($path_info == '/userinfo')
    handle_userinfo();
elseif($path_info == '/distributedinfo')
    handle_distributedinfo();
elseif($path_info == '/login')
    handle_login();
elseif($path_info == '/confirm_userinfo')
    handle_confirm_userinfo();
elseif($path_info == '/registration')
    handle_client_registration();
elseif(strpos($path_info, '/client') !== false)
    handle_client_operations();
elseif($path_info == '/sessioninfo')
    handle_session_info();
elseif($path_info == '/test')
    handle_test();
else
    handle_default($path_info);

exit();


function send_trusted_site_token() {
    error_log("SESSION = " . print_r($_SESSION, true));

    $GET=$_SESSION['get'];
    $rpfA=$_SESSION['rpfA'];
    error_log('send_trusted_site_token rpfA = ' . print_r($rpfA, true));
    error_log("AUTH_TIME = " . $_SESSION['auth_time']);
    $rpep=$GET['redirect_uri'];
    $atype = 'none';
    $client_id = $GET['client_id'];
    $response_types = explode(' ', $GET['response_type']);

    $is_code_flow = in_array('code', $response_types);
    $is_token_flow = in_array('token', $response_types );
    $is_id_token = in_array('id_token', $response_types);

    $trusted_site = $client_id;
    $site = db_get_user_site($_SESSION['username'], $trusted_site);

    $issue_at = strftime('%G-%m-%d %T');
    $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));
    error_log('Sending Trusted Site Token');


    if($site) {
        $site_policies = db_get_user_site_policies($_SESSION['username'], $client_id);
        $confirmed_attribute_list = array();
        if($site_policies && $site_policies->count()) {
            foreach($site_policies as $pol)
                $confirmed_attribute_list[] = $pol['property'];
        }
        $persona = $site->Persona['persona_name'];
        $rpfA['session_id'] = session_id();
        $rpfA['auth_time'] = $_SESSION['auth_time'];
        if($is_code_flow) {
            $code_info = create_token_info($_SESSION['username'], $confirmed_attribute_list, $GET, $rpfA);
            $code = $code_info['name'];
            unset($code_info['name']);
            $fields = array('client' => $GET['client_id'],
                            'issued_at' => $issue_at,
                            'expiration_at' => $expiration_at,
                            'token' => $code,
                            'details' => $details_str,
                            'token_type' => TOKEN_TYPE_AUTH_CODE,
                            'info' => json_encode($code_info)
                           );
            db_save_user_token($_SESSION['username'], $code, $fields);
        }
        if($is_token_flow) {
            $code_info = create_token_info($_SESSION['username'], $confirmed_attribute_list, $GET, $rpfA);
            $token = $code_info['name'];
            unset($code_info['name']);
            $issue_at = strftime('%G-%m-%d %T');
            $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));
            $fields = array('client' => $GET['client_id'],
                            'issued_at' => $issue_at,
                            'expiration_at' => $expiration_at,
                            'token' => $token,
                            'details' => $details_str,
                            'token_type' => TOKEN_TYPE_ACCESS,
                            'info' => json_encode($code_info)
                           );
            db_save_user_token($_SESSION['username'], $token, $fields);
        }
    }  else if($GET['response_type'] == 'id_token' && $GET['scope'] == 'openid') {
        // error_log('ONLY REQUESTING ID');
    }
    else {
        return false;
    }

    if($error)
        $url = "$rpep?error={$error}";
    else {
        $fragments = Array();
        if($is_token_flow || $is_id_token) {
            if($is_token_flow) {
                $fragments[] = "access_token=$token";
                $fragments[] = 'token_type=Bearer';
                $fragments[] = 'expires_in=3600';
            }
            if($GET['state'])
                $fragments[] = "state={$GET['state']}";
        }
        if($is_id_token) {
            $client_secret = NULL;
            $db_client = db_get_client($client_id);
            $sig_param = Array('alg' => 'none');
            $sig_key = NULL;
            if($db_client) {
                $client_secret = $db_client['client_secret'];
                if(!$db_client['id_token_signed_response_alg'])
                    $db_client['id_token_signed_response_alg'] = 'RS256';
                if(in_array($db_client['id_token_signed_response_alg'], Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'))) {
                    $sig_param['alg'] = $db_client['id_token_signed_response_alg'];
                    if(substr($db_client['id_token_signed_response_alg'], 0, 2) == 'HS') {
                        $sig_key = $db_client['client_secret'];
                    } elseif(substr($db_client['id_token_signed_response_alg'], 0, 2) == 'RS') {
                        $sig_param['jku'] = OP_JWK_URL;
                        $sig_param['kid'] = OP_SIG_KID;
                        $sig_key = array('key_file' => OP_PKEY, 'password' => OP_PKEY_PASSPHRASE);
                    }
                }
            }

            error_log("ID Token Using Sig Alg {$sig_param['alg']}");
            $id_token_obj = array(
                                    'iss' => SERVER_ID,
                                    'sub' => wrap_userid($db_client, $_SESSION['username']),
                                    'aud' => array($client_id),
                                    'exp' => time() + 5*(60),
                                    'iat' => time(),
                                    'ops' => session_id() . '.' . $_SESSION['ops']
                                 );
            if($GET['nonce'])
                $id_token_obj['nonce'] = $GET['nonce'];
            error_log("userid = " . $id_token_obj['sub'] . ' unwrapped = ' . unwrap_userid($id_token_obj['sub']));
            
            if(isset($rpfA['claims']) && isset($rpfA['claims']['id_token'])) {
                if((isset($rpfA['id_token']) && isset($rpfA['claims']['id_token'])) && array_key_exists('auth_time', $rpfA['claims']['id_token']))
                    $id_token_obj['auth_time'] = (int) $_SESSION['auth_time'];
                    
                if(array_key_exists('acr', $rpfA['claims']['id_token'])) {
                    if(array_key_exists('values', $rpfA['claims']['id_token']['acr'])) {
                        if(is_array($rpfA['claims']['id_token']['acr']['values']) && count($rpfA['claims']['id_token']['acr']['values']))
                            $id_token_obj['acr'] = $rpfA['claims']['id_token']['acr']['values'][0];
                    } else
                        $id_token_obj['acr'] = '0';
                }
            }
            if($sig_param['alg']) {
                $bit_length = substr($sig_param['alg'], 2);
                switch($bit_length) {
                    case '384':
                        $hash_alg = 'sha384';
                        break;
                    case '512':
                        $hash_alg = 'sha512';
                        break;                        
                    case '256':
                    default:
                        $hash_alg = 'sha256';
                    break;
                }
                $hash_length = (int) ((int) $bit_length / 2) / 8;
                if($code) {
                    error_log("************** got code");
                    $id_token_obj['c_hash'] = base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length));
                }
                if($token) {
                    error_log("************** got token");
                    $id_token_obj['at_hash'] = base64url_encode(substr(hash($hash_alg, $token, true), 0, $hash_length));
                }
                error_log("hash size = {$hash_lenth}");
            }
            

            $requested_id_token_claims = get_id_token_claims($rpfA);
            if($requested_id_token_claims) {
                $persona = db_get_user_persona($_SESSION['username'], $persona)->toArray();
                $persona_custom_claims = db_get_user_persona_custom_claims($_SESSION['username'], $_POST['persona']);
                foreach($persona_custom_claims as $pcc) {
                    $persona_claims[$pcc['claim']] = $pcc->PersonaCustomClaim[0]['value'];
                }
                foreach($confirmed_attribute_list as $key) {
                    if(array_key_exists($key, $requested_id_token_claims)) {
                        $prefix = substr($key, 0, 3);
                        if($prefix == 'ax.') {
                            $key = substr($key, 3);
                            $mapped_key = $key;
                            $kana = strpos($key, '_ja_kana_jp');
                            $hani = strpos($key, '_ja_hani_jp');
                            if($kana !== false)
                                $mapped_key = substr($key, 0, $kana) . '#ja-Kana-JP';
                            if($hani !== false)
                                $mapped_key = substr($key, 0, $hani) . '#ja-Hani-JP';
                            switch($mapped_key) {
                                case 'address' :
                                    $id_token_obj[$mapped_key] = array(
                                                                        'formatted' => $persona[$key]
                                                                      );
                                    break;
                                
                                case 'email_verified' :
                                case 'phone_number_verified' :
                                    if($persona[$key])
                                        $id_token_obj[$mapped_key] = true;
                                    else
                                        $id_token_obj[$mapped_key] = false;
                                    break;
                                
                                default :
                                    $id_token_obj[$mapped_key] = $persona[$key];
                                    break;
                            }
                        } elseif($prefix == 'cx.') {
                            $key = substr($key, 3);
                            $id_token_obj[$key] = $persona_claims[$key];
                        }
                    }                    
                }
            }                                 


            $id_token = jwt_sign($id_token_obj, $sig_param, $sig_key);
            if(!$id_token) {
                error_log("Unable to sign response for ID Token");
                send_bearer_error('400', 'invalid_request', 'Unable to sign response for ID Token');
            }

            if($db_client['id_token_encrypted_response_alg'] && $db_client['id_token_encrypted_response_enc']) {
                error_log("ID Token Encryption Algs {$db_client['id_token_encrypted_response_alg']} {$db_client['id_token_encrypted_response_enc']}");
                list($alg, $enc) = array($db_client['id_token_encrypted_response_alg'], $db_client['id_token_encrypted_response_enc']);
                if(in_array($alg, Array('RSA1_5', 'RSA-OAEP')) && in_array($enc, Array('A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512'))) {
                    $jwk_uri = '';
                    $encryption_keys = NULL;
                    if($db_client['jwks_uri']) {
                        $jwk = get_url($db_client['jwks_uri']);
                        if($jwk) {
                            $jwk_uri = $db_client['jwks_uri'];
                            $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                            if(!$encryption_keys || !count($encryption_keys))
                                $encryption_keys = NULL;
                        }
                    }
                    if(!$encryption_keys)
                        send_bearer_error('400', 'invalid_request', 'Unable to retrieve JWK key for encryption');
                    $id_token = jwt_encrypt($id_token, $encryption_keys[0], false, NULL, $jwk_uri, NULL, $alg, $enc, false);
                    if(!$id_token) {
                        error_log("Unable to encrypt response for ID Token");
                        send_bearer_error('400', 'invalid_request', 'Unable to encrypt response for ID Token');
                    }

                } else {
                    error_log("ID Token Encryption Algs $alg and $enc not supported");
                    send_bearer_error('400', 'invalid_request', 'Client registered unsupported encryption algs for ID Token');
                }
            }

            $fragments[] = "id_token=$id_token";
        }
        $queries = Array();
        if($is_code_flow) {
            if(count($fragments) == 0) {
                $queries[] = "code=$code";
                if($GET['state'])
                    $queries[] = "state={$GET['state']}";
            } else {
                array_unshift($fragments, "code=$code");
            }
        }
        
        if(count($queries))
            $query = '?' . implode('&', $queries);
        if(count($fragments))
            $fragment = '#' . implode('&', $fragments);
        $url="$rpep{$query}{$fragment}";
    }
    if($_SESSION['persist']=='on'){
        $username = $_SESSION['username'];
        $auth_time = $_SESSION['auth_time'];
        $ops = $_SESSION['ops'];
        $login = $_SESSION['login'];
        clean_session();
        $_SESSION['lastlogin']=time();
        $_SESSION['username']=$username;
        $_SESSION['auth_time']=$auth_time;
        $_SESSION['persist']='on';
        $_SESSION['ops'] = $ops;
        $_SESSION['login'] = $login;
        setcookie('ops', $_SESSION['ops'], 0, '/');
    } else {
        session_destroy();
    }
    header("Location:$url");
    return true;
}

/**
 * Read the identity file and compair password.
 * @param  String $username   Local ID of the user.
 * @param  String $password   User input password.
 * @return String true if OK, else false.
 */
function check_credential($username, $password) {
    $filename = "ids/" . $username . '.json';
    if(file_exists($filename)) {
  $jdentity = file_get_contents($filename);
  $arr = json_decode($jdentity,1);
  $sha1p = sha1($password);
  $cred = $arr["openid"]["cd:sha1pass"];
  if($sha1p==$cred){
    return 1;
  } else {
    return 0;
  }
    } else {
  echo $filename;
  return 0;
    }
}

/**
 * Show Login form.
 * @return String HTML Login form.
 */
function loginform($display_name = '', $user_id = ''){
   
   if($display_name && $user_id) {
       $userid_field = " <b>{$display_name}</b><input type='hidden' name='username_display' value='{$display_name}'><input type='hidden' name='username' value='{$user_id}'><br/>";
   } else {
       $userid_field = '<input type="text" name="username" value="alice">(or bob)';
   }
    
   $str='
  <html>
  <head><title>' . OP_SERVER_NAME . ' OP</title>
  <meta name="viewport" content="width=320">
  </head>
  <body style="background-color:#FFEEEE;">
  <h1>' . OP_SERVER_NAME . ' OP Login</h1>
  <form method="POST" action="' . $_SERVER['SCRIPT_NAME'] . '/login">
  Username:' . $userid_field . '<br />
  Password:<input type="password" name="password" value="wonderland">(or underland)<br />
  <input type="checkbox" name="persist" checked>Keep me logged in. <br />
  <input type="submit">
  </form>
  </body>
  </html>
  ';
  return $str;
}


/**
 * Show Confirmation Dialogue for Attributes.
 * @param  String $r     Request String (JSON)
 * @return String HTML to be shown.
 */
function confirm_userinfo(){
  $req=$_SESSION['rpfA'];
  $scopes = explode(' ', $req['scope']);
  $response_types = explode(' ', $req['response_type']);
  $offline_access = in_array('offline_access', $scopes) && in_array('code', $response_types) ? 'YES' : 'NO';
  $axlabel=get_default_claims();
  $claim_keys = array_keys($axlabel);
  $custom_claim_keys = array();
  $custom_claim_names = db_get_custom_claim_names();
  foreach($custom_claim_names as $custom_claim_name) {
    $custom_claim_keys[] = $custom_claim_name['claim'];
  }
  
  $rl = array();
  $requested_normal_claims = array();  
  $requested_custom_claims = array();  
  $requested_new_custom_claims = array();
//  error_log('axlabel = ' . print_r($axlabel, true));
//  error_log('claim_keys = '. print_r($claim_keys, true));
//  error_log('custom claim keys = '. print_r($custom_claim_keys, true));
  $requested_claims = get_all_requested_claims($req, $req['scope']);
  error_log('requested claims = ' . print_r($requested_claims, true));

  $tab_headers = array();
  $tabs = array();

  $personas = db_get_user_personas($_SESSION['username'])->toArray();

  for($i = 0; $i < count($personas); $i++) {
    if($personas[$i]['persona_name'] == 'Default') {
        $temp = $personas[$i];
        unset($personas[$i]);
        array_unshift($personas, $temp);
    }
  }

  $i = 0;
  foreach($personas as $persona) {
    ++$i;

    $persona_name = $persona['persona_name'];
    $persona_name_ui = ucfirst($persona_name);
    if(!$persona_name) {
        $persona_name_ui = 'Default';
        $persona_name = '';
    }
    array_push($tab_headers, "<li><a href='#tabs-$i'>$persona_name_ui</a></li>");

    $identity = $persona;
    $attributes = NULL;
    $persona_claims = array();
    $persona_custom_claims = db_get_user_persona_custom_claims($_SESSION['username'], $persona_name);
    foreach($persona_custom_claims as $pcc) {
        $persona_claims[$pcc['claim']] = $pcc->PersonaCustomClaim[0]['value'];
    }
    
    foreach($requested_claims as $claim => $required) {
        if($required == 1) {
            $readonly = ' readonly="readonly" onclick="this.checked = !this.checked;"';
            $star = "<font color='red'>*</font>";
        } else {
            $readonly = '';
            $star = '';
        }
        $claim_prefix = substr($claim, 0, 3);
        $claim_name = substr($claim, 3);
        switch($claim_prefix) {
            case 'ax.':
            $claim_label = "{$axlabel[$claim]}{$star}";
            $claim_value = $identity[$claim_name];
            break;
            
            case 'cx.':
            $claim_label = "cx-{$claim_name}{$star}";
            $claim_value = $persona_claims[$claim_name];
            break;
        }
//        error_log("claim = {$claim} label = {$claim_label} value = {$claim_value} $required $star");

        $attributes .= "<tr><td>{$claim_label}</td><td><input id='inputtext' name='$claim' type='text' value='{$claim_value}'></td><td><input type='checkbox' name='conf_{$claim}' value='1' checked {$readonly}></td></tr>\n";
    }

$persona_form_template = <<<EOF
  <div id='tabs-$i'>
  <div class="persona">
  <form method="POST" action="{$_SERVER['SCRIPT_NAME']}/confirm_userinfo">
  <input type="hidden" name="mode" value="ax_confirm">
  <input type="hidden" name="persona" value="$persona_name">
  <table cellspacing="0" cellpadding="0" width="600">
  <thead><tr><th>Attribute</th><th>Value</th><th>Confirm</th></tr></thead>
  $attributes
  <tr><td colspan="3">&nbsp;</td></tr>
  <thead><tr><td><b>Offline Access Requested</b></td><td>$offline_access</td><td></td></tr></thead>
  <tr><td colspan="3">&nbsp;</td></tr>
  <tr><td colspan="3">&nbsp;</td></tr>
  <tr><td colspan="3"><input type="checkbox" name="agreed" value="1" checked> Agree to Provide the above selected attributes. <br/>
  <input type="radio" name="trust" value="once" checked>Trust this site this time only <br />
  <input type="radio" name="trust" value="always" >Trust this site always <br/>
  </td></tr>
  <tr><td colspan="3"><input type="submit" name="confirm" value="confirmed"> <input type="submit" name="confirm" value="cancel" title="title"></td></tr></table>
  </form>
  </div>
  </div>
EOF;

    array_push($tabs, $persona_form_template);


  }

        if(DEBUG){
    echo "<pre>";
    echo "<h4>rpfA</h4>";
    print_r($rpfA);
    echo "<h4>axlabel</h4>";
    print_r($axlabel);
    echo "<h4>intersect</h4>";
    print_r($rl);


    echo "<h4>session</h4>";
    print_r($_SESSION);


    echo "<h4>identity assertion</h4>";
    print_r($identity);

    echo "<h4>return attributes</h4>";
    print_r($attribs);

    echo "</pre>";


  }

    $dirname = dirname($_SERVER['SCRIPT_NAME']);
$jquery = <<<EOF
    <link type="text/css" href="{$dirname}/css/smoothness/jquery-ui-1.8.6.custom.css" rel="stylesheet" />
    <script type="text/javascript" src="{$dirname}/js/jquery-1.4.2.min.js"></script>
    <script type="text/javascript" src="{$dirname}/js/jquery-ui-1.8.6.custom.min.js"></script>
    <script type="text/javascript">
      $(function(){

        // Tabs
        $('#tabs').tabs();

        //hover states on the static widgets
        $('#dialog_link, ul#icons li').hover(
          function() { $(this).addClass('ui-state-hover'); },
          function() { $(this).removeClass('ui-state-hover'); }
        );

      });
    </script>

    <style type="text/css">
      /*demo page css*/
      body{ font: 80% "Trebuchet MS", sans-serif; margin: 50px;}
      .demoHeaders { margin-top: 2em; }
      #dialog_link {padding: .4em 1em .4em 20px;text-decoration: none;position: relative;}
      #dialog_link span.ui-icon {margin: 0 5px 0 0;position: absolute;left: .2em;top: 50%;margin-top: -8px;}
      ul#icons {margin: 0; padding: 0;}
      ul#icons li {margin: 2px; position: relative; padding: 4px 0; cursor: pointer; float: left;  list-style: none;}
      ul#icons span.ui-icon {float: left; margin: 0 4px;}

      .persona table{ font: 80% "verdana", san-serif; }
      .persona td { font: 80% "verdana", san-serif;}
      .persona input#inputtext {font: 100% "verdana", san-serif; width: 460px;}

    </style>
EOF;

$headers = implode("\n", $tab_headers);
$personas = implode("\n", $tabs);
$tabs = <<<EOF
    <h2 class="demoHeaders">Personas</h2>
    <div id="tabs" style='width:700'>
      <ul>
        $headers
      </ul>
      $personas

    </div>

EOF;

  $str= '
  <html>
  <head><title>' . OP_SERVER_NAME . ' AX Confirm</title>
  <meta name="viewport" content="width=620">' . $jquery . '
  </head>
  <body style="background-color:#FFEEEE;">
  <h1>' . OP_SERVER_NAME . ' AX Confirm</h1>
  <h2>RP requests following AX values...</h2>' . $tabs . '
  </body>
  </html>
  ';
  return $str;
}



function create_token_info($uname, $attribute_list=NULL, $get=NULL, $req=NULL) {
    while(true) {
        $token_name = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
        if(!db_find_token($token_name))
            break;
    }
    $arr = Array();
    $arr['name'] = $token_name;
    $expires_in = 60; //in seconds
    $arr['e'] = time()+ $expires_in;
    $arr['u'] = $uname;
    $arr['l'] = $attribute_list;
    $arr['g'] = $get;
    $arr['r'] = $req;
    return $arr;
}


/**
 * Obtain the content of the URL.
 * @param  String $url      URL from which the content should be obtained.
 * @return String Response Text.
 */
function get_url($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $responseText = curl_exec($ch);
    $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if($http_status != 200) {
        error_log("Unable to fetch URL $url status = $http_status");
        return NULL;
    } else {
        error_log("GOT $responseText");
        return $responseText;
    }
}

/**
 * Clean up the SESSION variables.
 * @param String $persist  Whether to persist the login session
 * @return Int 1 if success. 0 if error.
 */
function clean_session($persist=0){
  unset($_SESSION['get']);
  unset($_SESSION['rpfA']);
  if(!$persist){
    unset($_SESSION['login']);
    unset($_SESSION['username']);
    unset($_SESSION['persist']);
    unset($_SESSION['ops']);
  }
  return true;
}




function preprint($str) {
    echo "<p><pre>\n";
    print_r($str);
    echo "\n</pre></p>\n";
}

function send_error($url, $error, $description=NULL, $error_uri=NULL, $state=NULL, $query=true, $http_error_code = '400') {
    error_log("url:{$url} error:{$error} desc:{$description} uri:{$error_uri} state:{$state} code:{$http_error_code}");
    if($url) {
        if($query) $separator = '?';
            else $separator = '#';
        $params = array('error' => $error);

        if($state) $params['state'] = $state;
        if($description) $params['error_description'] = $description;
        $url .= $separator . http_build_query($params);
        header("Location: $url");
        exit;
    } else {
        // echo "Error : $error : $description\n";
        $json = array();
        if($error)
            $json['error'] = $error;
        if($description)
            $json['error_description'] = $description;
        if($error_uri)
            $json['error_uri'] = $error_uri;
        if($state)
            $json['state'] = $state;

        $codes = Array(
                        '400' => 'Bad Request',
                        '401' => 'Unauthorized',
                        '403' => 'Forbidden',
                        '404' => 'Not Found',
                        '405' => 'Method Not Allowed'
                      );
    
        error_log("HTTP/1.0 {$http_error_code} {$codes[$http_error_code]}");
        header("HTTP/1.0 {$http_error_code} {$codes[$http_error_code]}");
        header('Content-Type: application/json');
        header("Cache-Control: no-store");
        header("Pragma: no-cache");
        echo json_encode($json);
        error_log(json_encode($json));
        exit;
    }
}

/*
400 Bad Request
The request could not be understood by the server due to malformed syntax. The client SHOULD NOT repeat the request without modifications.

401 Unauthorized
The request requires user authentication. The response MUST include a WWW-Authenticate header field (section 14.47) containing a challenge applicable to the requested resource. The client MAY repeat the request with a suitable Authorization header field (section 14.8). If the request already included Authorization credentials, then the 401 response indicates that authorization has been refused for those credentials. If the 401 response contains the same challenge as the prior response, and the user agent has already attempted authentication at least once, then the user SHOULD be presented the entity that was given in the response, since that entity might include relevant diagnostic information. HTTP access authentication is explained in "HTTP Authentication: Basic and Digest Access Authentication" [43].

402 Payment Required
This code is reserved for future use.

403 Forbidden
The server understood the request, but is refusing to fulfill it. Authorization will not help and the request SHOULD NOT be repeated. If the request method was not HEAD and the server wishes to make public why the request has not been fulfilled, it SHOULD describe the reason for the refusal in the entity. If the server does not wish to make this information available to the client, the status code 404 (Not Found) can be used instead.

404 Not Found
The server has not found anything matching the Request-URI. No indication is given of whether the condition is temporary or permanent. The 410 (Gone) status code SHOULD be used if the server knows, through some internally configurable mechanism, that an old resource is permanently unavailable and has no forwarding address. This status code is commonly used when the server does not wish to reveal exactly why the request has been refused, or when no other response is applicable.

405 Method Not Allowed
The method specified in the Request-Line is not allowed for the resource identified by the Request-URI. The response MUST include an Allow header containing a list of valid methods for the requested resource.

406 Not Acceptable
The resource identified by the request is only capable of generating response entities which have content characteristics not acceptable according to the accept headers sent in the request.


*/

function send_bearer_error($http_error_code, $error, $description=NULL) {

    $codes = Array(
                    '400' => 'Bad Request',
                    '401' => 'Unauthorized',
                    '403' => 'Forbidden',
                    '404' => 'Not Found',
                    '405' => 'Method Not Allowed'
                  );

    error_log("HTTP/1.0 {$http_error_code} {$codes[$http_error_code]}");
    header('WWW-Authenticate: Bearer error="' . $error . '"' . ($description ? ', error_description="' . $description . '"' : ''));
    header("HTTP/1.0 {$http_error_code} {$codes[$http_error_code]}");
//    header("Cache-Control: no-store");
//    header("Pragma: no-cache");
    exit;
}

function is_valid_registered_redirect_uri($redirect_uris, $uri) {
    $uris = explode('|', $redirect_uris);
    if(in_array($uri, $uris))
        return true;
    else
        return false;
}


/**
 * Decrypts and Verifies a JWT
 * @param $jwt
 * @param $client Array Client Info
 * @param $error  String error code error_decrypt or error_sig
 * @return mixed null/decoded payload
 */
function decrypt_verify_jwt($jwt, $client, &$error) {
    $response = NULL;
    $jwt_parts = jwt_to_array($jwt);
    if(isset($jwt_parts[0]['enc'])) { // encrypted
        $signed_jwt = jwt_decrypt($jwt, OP_PKEY, true);
        if(!$signed_jwt) {
            log_error('Unable to decrypt object');
            $error = 'error_decrypt';
            return NULL;
        } else
            log_debug("decrypted object = %s", $signed_jwt);
    } else
        $signed_jwt = $jwt;
    if($signed_jwt) {
        list($header, $payload, $sig) = jwt_to_array($signed_jwt);
        $verified = false;
        if(substr($header['alg'], 0, 2) == 'HS') {
            $verified = jwt_verify($signed_jwt, $client['client_secret']);
        } elseif(substr($header['alg'], 0, 2) == 'RS') {
            $pubkeys = array();
            if($client['jwks_uri'])
                $pubkeys['jku'] = $client['jwks_uri'];
            $verified = jwt_verify($signed_jwt, $pubkeys);
        } elseif($header['alg'] == 'none')
            $verified = true;
        log_debug("Signature Verification = $verified");
        if($verified)
            $response = $payload;
        else
            $error = 'error_sig';
    }
    return $response;
}

function handle_auth() {
    $state = isset($_REQUEST['state']) ? $_REQUEST['state'] : NULL;
    $error_page = isset($_REQUEST['redirect_uri']) ? $_REQUEST['redirect_uri'] : OP_INDEX_PAGE;

    try{
        if(!isset($_REQUEST['client_id']))
            throw new OidcException('invalid_request', 'no client');
        // check client id
        $client = db_get_client($_REQUEST['client_id']);
        if(!$client)
            throw new OidcException('unauthorized_client', 'Client ID not found');

        if(isset($_REQUEST['redirect_uri'])) {
            if(!is_valid_registered_redirect_uri($client['redirect_uris'], $_REQUEST['redirect_uri']))
                throw new OidcException('invalid_request', 'no matching redirect_uri');
        } else {
            if($client['redirect_uris']) {
                $uris = explode('|', $client['redirect_uris']);
                if(count($uris) > 1)
                    throw new OidcException('invalid_request', 'no redirect_uri, but multiple registered');
                $_REQUEST['redirect_uri'] = $uris[0];
                $_GET['redirect_uri'] = $uris[0];
            } else
                throw new OidcException('invalid_request', 'no redirect_uris registered');
        }

        if(!isset($_REQUEST['response_type']))
            throw new OidcException('invalid_request', 'no response_type');
        $response_types = explode(' ', $_REQUEST['response_type']);
        $known_response_types = array('code', 'token', 'id_token');
        if(count(array_diff($response_types, $known_response_types)))
            throw new OidcException('invalid_response_type', "Unknown response_type {$_REQUEST['response_type']}");

        if(!isset($_REQUEST['scope']))
            throw new OidcException('invalid_request', 'no scope');
        $scopes = explode(' ', $_REQUEST['scope']);
        if(!in_array('openid', $scopes))
            throw new OidcException('invalid_scope', 'no openid scope');

        if(in_array('token', $response_types) || in_array('id_token', $response_types)) {
            if(!isset($_REQUEST['nonce']))
                throw new OidcException('invalid_request', 'no nonce');
        }

        $_SESSION['get'] = $_GET;
        $request_uri = isset($_REQUEST['request_uri']) ? $_REQUEST['request_uri'] : NULL;

        $requested_userid = NULL;
        $requested_userid_display = NULL;
        $request_object = NULL;
        if($request_uri) {
            $request_object = get_url($request_uri);
            if(!$request_object)
                throw new OidcException('invalid_request', "Unable to fetch request file $request_uri");
        } elseif(isset($_REQUEST['request']))
            $request_object = $_REQUEST['request'];
        if(isset($request_object)) {
            $cryptoError = '';
            $payload = decrypt_verify_jwt($request_object, $client, $cryptoError);
            if(!isset($payload)) {
                if($cryptoError == 'error_decrypt')
                    throw new OidcException('invalid_request', 'Unable to decrypt request object');
                elseif($cryptoError == 'error_sig')
                    throw new OidcException('invalid_request', 'Unable to verify request object signature');
            } else {

                if(isset($payload['claims']['id_token'])) {
                    if(array_key_exists('sub', $payload['claims']['id_token']) && isset($payload['claims']['id_token']['sub']['value'])) {
                        $requested_userid_display = $payload['claims']['id_token']['sub']['value'];
                        $requested_userid = unwrap_userid($payload['claims']['id_token']['sub']['value']);
                        if(!db_get_user($requested_userid))
                            throw new OidcException('invalid_request', 'Unrecognized userid in request');
                    }
                }

                if(isset($_GET['claims']))
                    $_GET['claims'] = json_decode($_GET['claims'], true);
                $merged_req = array_merge($_GET, $payload);
                if(!array_key_exists('max_age', $merged_req) && $client['default_max_age'])
                    $merged_req['max_age'] = $client['default_max_age'];
                if($merged_req['max_age'])
                    $merged_req['claims']['id_token']['auth_time'] =  array('essential' => true);
                if((!$merged_req['claims']['id_token'] || !array_key_exists('auth_time', $merged_req['claims']['id_token'])) && $client['require_auth_time'])
                    $merged_req['claims']['id_token']['auth_time'] = array('essential' => true);
                if(!$merged_req['claims']['id_token'] || !array_key_exists('acr', $merged_req['claims']['id_token'])) {
                    if($merged_req['acr_values'])
                        $merged_req['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode(' ', $merged_req['acr_values']));
                    elseif($client['default_acr_values'])
                        $merged_req['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode('|', $client['default_acr_values']));
                }
                $_SESSION['rpfA'] = $merged_req;

                log_debug("rpfA = " . print_r($_SESSION['rpfA'], true));
                foreach(Array('client_id', 'response_type', 'scope', 'nonce', 'redirect_uri') as $key) {
                    if(!isset($payload[$key]))
                        log_error("missing {$key} in payload => " . print_r($payload, true));
//                      throw new OidcException('invalid_request', 'Request Object missing required parameters');
                }

                log_debug("payload => " . print_r($payload, true));
                foreach($payload as $key => $value) {
                    if(isset($_REQUEST[$key]) && (strcmp($_REQUEST[$key],$value))) {
                        log_debug("key : {$key} value:%s", print_r($value, true));
                        throw new OidcException('invalid_request', "Request Object Param Values do not match request '{$key}' '{$_REQUEST[$key]}' != '{$value}'");
                    }
                }
            }
        } else {
            if(isset($_GET['id_token_hint'])) {
                $cryptoError = '';
                $payload = decrypt_verify_jwt($_REQUEST['id_token_hint'], $client, $cryptoError);
                if(!isset($payload)) {
                    if($cryptoError == 'error_decrypt')
                        throw new OidcException('invalid_request', 'Unable to decrypt request object');
                    elseif($cryptoError == 'error_sig')
                        throw new OidcException('invalid_request', 'Unable to verify request object signature');
                } else {
                    $requested_userid_display = $payload['sub'];
                    $requested_userid = unwrap_userid($payload['sub']);
                    if(!db_get_user($requested_userid))
                        throw new OidcException('invalid_request', 'Unrecognized userid in ID Token');
                }
            }

            if(!array_key_exists('max_age', $_REQUEST) && $client['default_max_age'])
                $_REQUEST['max_age'] = $client['default_max_age'];
            if($_REQUEST['max_age'])
                $_REQUEST['claims']['id_token']['auth_time'] =  array('essential' => true);
            if((!$_REQUEST['claims']['id_token'] || !array_key_exists('auth_time', $_REQUEST['claims']['id_token'])) && $client['require_auth_time'])
                $_REQUEST['claims']['id_token']['auth_time'] = array('essential' => true);
            if(!$_REQUEST['claims']['id_token'] || !array_key_exists('acr', $_REQUEST['claims']['id_token'])) {
                if($_REQUEST['acr_values'])
                    $_REQUEST['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode(' ', $_REQUEST['acr_values']));
                elseif($client['default_acr_values'])
                    $_REQUEST['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode('|', $client['default_acr_values']));
            }

            $_SESSION['rpfA'] = $_REQUEST;
        }
        log_debug("prompt = " . $_SESSION['rpfA']['prompt']);
        $prompt = $_SESSION['rpfA']['prompt'] ? explode(' ', $_SESSION['rpfA']['prompt']) : array();
        $num_prompts = count($prompt);
        if($num_prompts > 1 && in_array('none', $prompt))
            throw new OidcException('interaction_required', "conflicting prompt parameters {$_SESSION['rpfA']['prompt']}");
        if($num_prompts == 1 && in_array('none', $prompt))
            $showUI = false;
        else
            $showUI = true;
        log_debug("num prompt = {$num_prompts}" . print_r($prompt, true));
        if($_SESSION['username']) {
            if(in_array('login', $prompt)){
                echo loginform($requested_userid_display, $requested_userid);
                exit();
            }
            if(isset($_SESSION['rpfA']['max_age'])) {
                if((time() - $_SESSION['auth_time']) > $_SESSION['rpfA']['max_age']) {
                    if(!$showUI)
                        throw new OidcException('interaction_required', 'max_age exceeded and prompt set to none');
                    echo loginform($requested_userid_display, $requested_userid);
                    exit;
                }
            }
            if($requested_userid) {
                if($_SESSION['username'] != $requested_userid) {
                    if(!$showUI)
                        throw new OidcException('interaction_required', 'requested account is different from logged in account, no UI requested');
                    else {
                        echo loginform($requested_userid_display, $requested_userid);
                        exit;
                    }
                }
            }

            if(in_array('consent', $prompt)){
                echo confirm_userinfo();
                exit();
            }
            if(db_get_user_trusted_client($_SESSION['username'], $_REQUEST['client_id'])) {
                if(!$showUI)
                    throw new OidcException('interaction_required', 'consent needed and prompt set to none');
                echo confirm_userinfo();
            } else
                send_response($_SESSION['username'], true);
        } else {
            if(!$showUI)
                throw new OidcException('interaction_required', 'unauthenticated and prompt set to none');
            echo loginform($requested_userid_display, $requested_userid);
        }
    }
    catch(OidcException $e) {
        log_debug("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, $e->error_code, $e->desc, NULL, $state);
    }
    catch(Exception $e) {
        log_debug("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, 'invalid_request', $e->getMessage(), NULL, $state);
    }
}


function is_client_authenticated() {
    $auth_type = '';
    if(isset($_REQUEST['client_assertion_type'])) {
        $auth_type = $_REQUEST['client_assertion_type'];
        error_log("client_assertion_type auth $auth_type\n");
        if($auth_type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
            send_error(NULL, 'unauthorized_client', 'Unknown client_assertion_type');
        $jwt_assertion = $_REQUEST['client_assertion'];
        if(!isset($jwt_assertion))
            send_error(NULL, 'unauthorized_client', 'client_assertion not available');
        list($jwt_header, $jwt_payload, $jwt_sig) = jwt_to_array($jwt_assertion);
        if($jwt_payload['iss'] != $jwt_payload['sub'])
            send_error(NULL, 'invalid request', 'JWT iss and prn mismatch');
        $client_id = $jwt_payload['iss'];
        error_log('header = ' . print_r($jwt_header, true) . "\npayload = " . print_r($jwt_payload, true) . "\nSig = " . print_r($jwt_sig, true));
        error_log("assertion = $jwt_assertion\n");
    } elseif(isset($_SERVER['PHP_AUTH_USER'])) {
        $client_id = $_SERVER['PHP_AUTH_USER'];
        if(isset($_SERVER['PHP_AUTH_PW']))
          $client_secret = $_SERVER['PHP_AUTH_PW'];
        $auth_type = 'client_secret_basic';
    } elseif(isset($_REQUEST['client_id'])) {
        $client_id = $_REQUEST['client_id'];
        if(isset($_REQUEST['client_secret']))
          $client_secret = $_REQUEST['client_secret'];
        $auth_type = 'client_secret_post';
    } else
        send_error(NULL, 'invalid_request', 'Unknown authentication type');

    if(!$client_id || !($client_secret || $jwt_assertion))
         send_error(NULL, 'invalid_client', 'no client or secret');

    // perform client_id and client_secret check
    $db_client = db_get_client($client_id);
    if($db_client) {
        error_log("**********************{$db_client['client_id']}\n{$db_client['x509_uri']}\n{$db_client['id_token_signed_response_alg']}");
        $db_client = $db_client->toArray();
        $token_endpoint_auth_method = $db_client['token_endpoint_auth_method'];
        if(!$token_endpoint_auth_method)
            $token_endpoint_auth_method = 'client_secret_basic';
    } else send_error(NULL, 'unauthorized_client', 'client_id not found');

//    if($token_endpoint_auth_method != $auth_type)
//        send_error(NULL, 'unauthorized_client', 'mismatched token endpoint auth type');

    switch($token_endpoint_auth_method) {
        case 'client_secret_basic':
        case 'client_secret_post' :
            $client_authenticated = db_check_client_credential($client_id, $client_secret);
            error_log("authenticating client_id $client_id with client_secret $client_secret\nResult : $client_authenticated");
        break;

        case 'client_secret_jwt' :
            $sig_verified = jwt_verify($jwt_assertion, $db_client['client_secret']);
            if(substr($_SERVER['PATH_INFO'], 0, 2) == '/1')
                $audience = OP_ENDPOINT . '/1/token';
            else
                $audience = OP_ENDPOINT . '/token';
            $aud_verified = $jwt_payload['aud'] == $audience;
            $now = time();
            $time_verified = ($now >= $jwt_payload['iat']) && ($now <= $jwt_payload['exp']);
            if(!$sig_verified)
                error_log("Sig not verified");
            if(!$aud_verified)
                error_log('Aud not verified');
            if(!$time_verified)
                error_log('Time not verified');
            $client_authenticated = $sig_verified && $aud_verified && $time_verified;
            error_log(" client_secret_jwt Result : $client_authenticated $sig_verified $aud_verified $time_verified");
        break;

        case 'private_key_jwt' :
                $pubkeys = array();
                if($db_client['jwks_uri'])
                    $pubkeys['jku'] = $db_client['jwks_uri'];
            $sig_verified = jwt_verify($jwt_assertion, $pubkeys);
//            $sig_verified = jwt_verify($jwt_assertion, $pem);
            if(substr($_SERVER['PATH_INFO'], 0, 2) == '/1')
                $audience = OP_ENDPOINT . '/1/token';
            else
                $audience = OP_ENDPOINT . '/token';
            $aud_verified = $jwt_payload['aud'] == $audience;
            $now = time();
            $time_verified = ($now >= $jwt_payload['iat']) && ($now <= $jwt_payload['exp']);
            if(!$sig_verified)
                error_log("Sig not verified");
            if(!$aud_verified)
                error_log('Aud not verified');
            if(!$time_verified)
                error_log('Time not verified');
            $client_authenticated = $sig_verified && $aud_verified && $time_verified;
            error_log(" private_key_jwt Result : $client_authenticated $sig_verified $aud_verified $time_verified");
        break;

        default :
            send_error(NULL, 'invalid_request', 'Unknown authentication type');
    }
    return $client_authenticated;
}


function handle_token() {

    try
    {
        $redirect_uri = $_REQUEST['redirect_uri'];
        $grant_type = strtolower($_REQUEST['grant_type']);
        if(!$grant_type || $grant_type != 'authorization_code')
            throw new OidcException('unsupported_grant_type', "{$grant_type} is not supported");
        $code = $_REQUEST['code'];
        if(!$code)
            throw new OidcException('invalid_authorization_code', 'No auth code');
        // check code
        $auth_code = db_find_auth_code($code);
        if(!$auth_code)
            throw new OidcException('invalid_authorization_code', 'no such code');
        $request_info = json_decode($auth_code['info'], true);
        $client_authenticated = is_client_authenticated();
        if($client_authenticated) {
            // TODO
            // lookup authorization code

            while(true) {
                $token_name = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
                if(!db_find_token($token_name))
                    break;
            }
            $issue_at = strftime('%G-%m-%d %T');
            $expiration_at = strftime('%G-%m-%d %T', time() + (30*60));
            $fields = array('client' => $auth_code['client'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $token_name,
                'details' => '',
                'token_type' => TOKEN_TYPE_ACCESS,
                'info' => $auth_code['info']
            );
            db_save_user_token($auth_code->Account['login'], $token_name, $fields);
            $access_token = $token_name;

            $response_types = explode(' ', $request_info['g']['response_type']);
            $scopes = explode(' ', $request_info['g']['scope']);
            $prompts = explode(' ', $request_info['g']['prompt']);
            if(in_array('openid', $scopes)) {

                $client_secret = null;
                $nonce = isset($GET['nonce']) ? $GET['nonce'] : null;
                $c_hash = null;
                $at_hash = null;
                $ops = null;
                $auth_time = null;
                $acr = null;
                $idt_claims = array();
                $sig = null;
                $alg = null;
                $enc = null;
                $client_secret = null;
                $jwk_uri = null;

                $db_client = db_get_client($auth_code['client']);
                $sig_param = Array('alg' => 'none');
                $sig_key = NULL;
                if(!$db_client)
                    throw new OidcException('invalid_request', 'invalid client');
                $sig = $db_client['id_token_signed_response_alg'];
                if(!isset($sig))
                    $sig = 'RS256';
                $alg = $db_client['id_token_encrypted_response_alg'];
                $enc = $db_client['id_token_encrypted_response_enc'];
                $client_secret = $db_client['client_secret'];
                $jwk_uri = $db_client['jwks_uri'];

                error_log("ID Token Using Sig Alg {$sig_param['alg']}");
//                $id_token_obj = array(
//                    'iss' => SERVER_ID,
//                    'sub' => wrap_userid($db_client, $request_info['u']),
//                    'aud' => array($auth_code['client']),
//                    'exp' => time() + 5*(60),
//                    'iat' => time()
//                );

                if(isset($request_info['r']['session_id'])) {
                    session_id($request_info['r']['session_id']);
                    if(session_start()) {
                        if(isset($_SESSION['ops'])) {
                            $id_token_obj['ops'] = $request_info['r']['session_id'] . '.' . $_SESSION['ops'];
                        } else {
                            error_log("********** no ops in sessionid {$request_info['r']['session_id']} => " . print_r($_SESSION, true) );
                        }
                    }
                }

                if($request_info['g']['nonce'])
                    $nonce = $request_info['g']['nonce'];
                error_log("userid = " . $id_token_obj['sub'] . ' unwrapped = ' . unwrap_userid($id_token_obj['sub']));
                if($sig) {
                    $bit_length = substr($sig, 2);
                    switch($bit_length) {
                        case '384':
                            $hash_alg = 'sha384';
                            break;
                        case '512':
                            $hash_alg = 'sha512';
                            break;
                        case '256':
                        default:
                            $hash_alg = 'sha256';
                            break;
                    }
                    $hash_length = (int) ((int) $bit_length / 2) / 8;
//                    if($code)
//                        $c_hash = base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length));
                    if($token_name)
                        $at_hash = base64url_encode(substr(hash($hash_alg, $token_name, true), 0, $hash_length));
                }

                if(isset($request_info['r']['claims']) && isset($request_info['r']['claims']['id_token']) ) {
                    if(array_key_exists('auth_time', $request_info['r']['claims']['id_token'])) {
                        if(isset($request_info['r']['session_id'])) {
                            session_id($request_info['r']['session_id']);
                            if(session_start()) {
                                if(isset($_SESSION['auth_time'])) {
                                    $auth_time = (int) $_SESSION['auth_time'];
                                }
                            }
                        }
                        if(!isset($auth_time)) {
                            if(isset($request_info['r']['auth_time']) ) {
                                $auth_time = (int) $request_info['r']['auth_time'];
                            }
                        }
                    }

                    if(array_key_exists('acr', $request_info['r']['claims']['id_token'])) {
                        if(array_key_exists('values', $request_info['r']['claims']['id_token']['acr'])) {
                            if(is_array($request_info['r']['claims']['id_token']['acr']['values']) && count($request_info['r']['claims']['id_token']['acr']['values']))
                                $acr = $request_info['r']['claims']['id_token']['acr']['values'][0];
                        } else
                            $acr = '0';

                    }
                }

                $requested_id_token_claims = get_id_token_claims($request_info['r']);
                log_debug('requested idtoken claims = %s', print_r($requested_id_token_claims, true));
                if($requested_id_token_claims) {
                    $db_user = db_get_user($request_info['u']);
                    if(!$db_user)
                        throw new OidcException('invalid_request', 'no such user');
                    $idt_claims = get_account_claims($db_user, array_intersect_key($request_info['l'], $requested_id_token_claims));
                }
                $id_token_obj = make_id_token(wrap_userid($db_client, $request_info['u']), SERVER_ID, $db_client['client_id'], $idt_claims, $nonce, $c_hash, $at_hash, $auth_time, $ops, $acr );

                log_debug('handle_token id_token_obj = %s', print_r($id_token_obj, true));
                $cryptoError = '';
                $id_token = sign_encrypt($id_token_obj, $sig, $alg, $enc, $jwk_uri, $client_secret, $cryptoError);

                if(!$id_token) {
                    log_error("ID Token cryptoError = %s", $cryptoError);
                    throw new OidcException('invalid request', "Idtoken crypto error {$cryptoError}");
                }
            }

            if(in_array('offline_access', $scopes) && in_array('code', $response_types) && in_array('token', $response_types) && in_array('consent', $prompts)) {
                while(true) {
                    $refresh_token_name = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
                    if(!db_find_token($refresh_token_name))
                        break;
                }
                $fields['token'] = $refresh_token_name;
                $fields['token_type'] = TOKEN_TYPE_REFRESH;
                $fields['expiration_at'] = strftime('%G-%m-%d %T', time() + (24*60*60));
                db_save_user_token($auth_code->Account['login'], $refresh_token_name, $fields);
                $refresh_token = $refresh_token_name;
            }


            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            header("Pragma: no-cache");
            $token_response = array(
                'access_token' => $access_token,
                'token_type' => 'Bearer',
                'expires_in' => 3600
            );
            if($refresh_token)
                $token_response['refresh_token'] = $refresh_token;
            if($id_token)
                $token_response['id_token'] = $id_token;
            log_debug('token response = %s',  print_r($token_response, true));
            echo json_encode($token_response);
        } else
            send_error(NULL, 'invalid_client', 'invalid client credentials');
    }
    catch(OidcException $e)
    {
        send_error(NULL, $e->error_code, $e->desc);
    }
    catch(BearerException $e)
    {
        send_bearer_error('400', $e->error_code, $e->desc);
    }

}

function get_default_claims()
{
    return array(
                  "name" => "Full Name",
                  "name_ja_kana_jp" => "Full Name (Kana)",
                  "name_ja_hani_jp" => "Full Name (Kanji)",
                  "given_name" => "First Name",
                  "given_name_ja_kana_jp" => "First Name (Kana)",
                  "given_name_ja_hani_jp" => "First Name (Kanji)",
                  "family_name" => "Last Name",
                  "family_name_ja_kana_jp" => "Last Name (Kana)",
                  "family_name_ja_hani_jp" => "Last Name (Kanji)",
                  "middle_name" => "Middle Name",
                  "middle_name_ja_kana_jp" => "Middle Name (Kana)",
                  "middle_name_ja_hani_jp" => "Middle Name (Kanji)",
                  "nickname" => "Nickname",
                  "preferred_username" => "Preferred Username",
                  "profile" => "Profile Link",
                  "picture" => "Picture Link",
                  "website" => "Web Site",
                  "email" => "E-Mail",
                  "email_verified" => "Email Verified",
                  "gender" => "Gender",
                  "birthdate" => "BirthDate",
                  "zoneinfo" => "Zone",
                  "locale" => "Locale",
                  "phone_number" => "Phone Number",
                  "phone_number_verified" => "Phone Number Verified",
                  "address" => "Address",
                  "updated_at" => "Updated At"
                );

}


function get_requested_claims($request, $subkeys) {
    
//    $default_claims=get_default_claims();

    $requested_claims = array();
    foreach($subkeys as $subkey) {
        if(isset($request['claims']) && is_array($request['claims']) && $request['claims'][$subkey] &&  is_array($request['claims'][$subkey]) && count($request['claims'][$subkey])) {
            foreach($request['claims'][$subkey] as $key => $value) {
                $pound = strpos($key, '#');
                $key_name = $key;
                if($pound !== false) {
                    $temp = substr($key, 0, $pound);
                    $locale = substr($key, $pound+1);
                    if($locale == 'ja-Kana-JP')
                        $key_name = $temp . '_ja_kana_jp';
                    elseif($locale == 'ja_Hani-JP')
                        $key_name = $temp . '_ja_hani_jp';
//                    if(!array_key_exists('ax.' . $key_name, $default_claims))
//                        $key_name = $key;
                }
                if(in_array($key_name, array('auth_time', 'acr', 'sub')))
                    continue;
                $required = 0;
                if(is_array($value) && $value['essential'])
                    $required = 1;
                $requested_claims[$key_name] = max($requested_claims[$key_name], $required);
            }
        } else {
            error_log("get_requested_claims [{$subkey}] = " . isset($request['claims'][$subkey]) . "  count = " . count($request['claims'][$subkey]) . ' claims = ' . print_r($request['claims'][$subkey], true));
        }
    }
    return $requested_claims;
}

function get_userinfo_claims($request, $scopes) {
    $requested_claims = array();
    $profile_claims = array();
    error_log("get_userinfo_claims " . print_r($request, true) . "scopes = " . print_r($scopes, true));
    if(isset($request['claims']) && isset($request['claims']['userinfo']))
        $requested_claims = get_requested_claims($request, array('userinfo'));
    if(is_string($scopes))
        $scopes = explode(' ', $scopes);
    error_log("** scopes = " . print_r($scopes, true));
    if(!is_array($scopes)) {
        error_log(!!!'returning empty array');
        return array();
    }
    if(in_array('email', $scopes)) {
        $requested_claims['email'] = 0;
        $requested_claims['email_verified'] = 0;
    }
    if(in_array('address', $scopes))
        $requested_claims['address'] = 0;
    if(in_array('phone', $scopes)) {
        $requested_claims['phone_number'] = 0;
        $requested_claims['phone_number_verified'] = 0;
    }
    if(in_array('profile', $scopes)) {
        $profile_claims=get_default_claims();
        unset($profile_claims['email']);
        unset($profile_claims['email_verified']);
        unset($profile_claims['address']);
        unset($profile_claims['phone_number']);
        unset($profile_claims['phone_number_verified']);
        if(!isset($request['userinfo']['preferred_locales']))
            $request['userinfo']['preferred_locales'] = array();
        if(!in_array('ja-Kana-JP', $request['userinfo']['preferred_locales'])) {
            unset($profile_claims['name_ja_kana_jp']);
            unset($profile_claims['given_name_ja_kana_jp']);
            unset($profile_claims['family_name_ja_kana_jp']);
            unset($profile_claims['middle_name_ja_kana_jp']);
        }
        if(!in_array('ja-Hani-JP', $request['userinfo']['preferred_locales'])) {
            unset($profile_claims['name_ja_hani_jp']);
            unset($profile_claims['given_name_ja_hani_jp']);
            unset($profile_claims['family_name_ja_hani_jp']);
            unset($profile_claims['middle_name_ja_hani_jp']);
        }
        $profile_keys = array_keys($profile_claims);
        $num = count($profile_keys);
        if($num)
            $profile_claims = array_combine($profile_keys, array_fill(0, $num, 0));
    }
    return array_merge($requested_claims, $profile_claims);
}

function get_id_token_claims($request) {
    return get_requested_claims($request, array('id_token'));
}

function get_all_requested_claims($request, $scope) {
    $userinfo_claims = get_userinfo_claims($request, $scope);
    error_log("userinfo claims = " . print_r($userinfo_claims, true));
    $id_token_claims = get_id_token_claims($request);
    error_log("id_token claims = " . print_r($id_token_claims, true));
    $userinfo_keys = array_keys($userinfo_claims);
    $id_token_keys = array_keys($id_token_claims);
    $all_keys = array_unique(array_merge($userinfo_keys, $id_token_keys));
    sort($all_keys, SORT_STRING);
    error_log("unique keys = " . print_r($all_keys, true));
    $requested_claims = array();
    foreach($all_keys as $key) {
        $requested_claims[$key] = max($userinfo_claims[$key], $id_token_claims[$key]);
    }
    error_log("requested_claims = " . print_r($requested_claims, true));
    return $requested_claims;
}

function handle_userinfo() {
    try
    {
        $token = $_REQUEST['access_token'];
        if(!$token) {
            $token = get_bearer_token();
            if(!$token)
                throw new BearerException('invalid_request', 'No Access Token');
        }
        // check code
        $token = db_find_access_token($token);
        if(!$token)
            throw new BearerException('invalid_request', 'Cannot find Access Token');
        $db_client = db_get_client($token['client']);
        if(!$db_client)
            throw new BearerException('invalid_request', 'Invalid Client ID');
        $tinfo = json_decode($token['info'], true);
        $userinfo = Array();

        $db_user = db_get_user($tinfo['u']);
        $scopes = explode(' ', $tinfo['g']['scope']);
        if(in_array('openid', $scopes)) {
            $userinfo['sub'] = wrap_userid($db_client, $tinfo['u']);
        }
        log_debug("userid = %s  unwrapped = %s" . $userinfo['sub'], unwrap_userid($userinfo['sub']));
        $requested_userinfo_claims = get_userinfo_claims($tinfo['r'], $tinfo['r']['scope']);

        log_debug("ALLOWED CLAIMS = %s", print_r($tinfo['l'], true));
        log_debug("REQUESTED_USER_INFO = %s", print_r($requested_userinfo_claims, true));

        $sig = $db_client['userinfo_signed_response_alg'];
        $alg = $db_client['userinfo_encrypted_response_alg'];
        $enc = $db_client['userinfo_encrypted_response_enc'];
        $client_secret = $db_client['client_secret'];
        $jwk_uri = $db_client['jwks_uri'];

        $userinfo_claims = get_account_claims($db_user, array_intersect_key($tinfo['l'], $requested_userinfo_claims));
        $userinfo = array_merge($userinfo, $userinfo_claims);
        $sig_param = Array('alg' => 'none');
        $sig_key = NULL;

        if($sig || ($alg && $enc)) {
            $cryptoError = '';
            $userinfo_jwt = sign_encrypt($userinfo, $sig, $alg, $enc, $jwk_uri, $client_secret, $cryptoError);
            header("Content-Type: application/jwt");
            header("Cache-Control: no-store");
            header("Pragma: no-cache");

            log_debug('userinfo response = %s', $userinfo_jwt);
            echo $userinfo_jwt;

        } else {
            header("Cache-Control: no-store");
            header("Pragma: no-cache");
            header("Content-Type: application/json");
            log_debug('userinfo response = %s', json_encode($userinfo));
            echo json_encode($userinfo);

        }
    }
    catch(BearerException $e)
    {
        send_bearer_error('401', $e->error_code, $e->desc);
    }
    catch(OidcException $e)
    {
        send_error('', $e->error_code, $e->desc);
    }
}


function get_bearer_token()
{
    $headers = array();
    $tmp_headers = apache_request_headers();
    foreach ($tmp_headers as $header => $value) {
        log_debug("$header: $value\n");
        $headers[strtolower($header)] = $value;
    }
    $authorization = $headers['authorization'];
    log_debug('headers = %s', print_r($headers, true));
    log_debug("authorization header = $authorization \n");
    if($authorization) {
        $pieces = explode(' ', $authorization);
        log_debug('pieces = ', print_r($pieces, true));
        if(strcasecmp($pieces[0], 'bearer') != 0) {
            log_error('No Bearer Access Token in Authorization Header');
            return null;
        }
        $token = rtrim($pieces[1]);
        log_debug("token = $token");
        return $token;
    }
    return null;
}


function handle_distributedinfo() {

    try
    {
        //TODO
        // Add stuff here
        $token = $_REQUEST['access_token'];
        if(!$token) {
            $token = get_bearer_token();
            if(!$token)
                throw new BearerException('invalid_request', 'No Access Token');
        }
        // check code
        $token = db_find_access_token($token);
        if(!$token)
            throw new BearerException('invalid_request', 'Cannot find Access Token');
        $db_client = db_get_client($token['client']);
        if(!$db_client)
            throw new BearerException('invalid_request', 'Invalid Client ID');
        $tinfo = json_decode($token['info'], true);
        $userinfo = Array();
//    $persona = Array();
        $persona = db_get_user_persona($tinfo['u'], $tinfo['p'])->toArray();
        $scopes = explode(' ', $tinfo['g']['scope']);
        if(in_array('openid', $scopes)) {
            $userinfo['sub'] = wrap_userid($db_client, $tinfo['u']);
        }
        error_log("userid = " . $userinfo['sub'] . ' unwrapped = ' . unwrap_userid($userinfo['sub']));
        $requested_userinfo_claims = get_userinfo_claims($tinfo['r'], $tinfo['r']['scope']);
        $persona_custom_claims = db_get_user_persona_custom_claims($tinfo['u'], $tinfo['p']);
        foreach($persona_custom_claims as $pcc) {
            $persona_claims[$pcc['claim']] = $pcc->PersonaCustomClaim[0]['value'];
        }

        error_log("ALLOWED CLAIMS = " . print_r($tinfo['l'], true));
        error_log("REQUESTED_USER_INFO = \n" . print_r($requested_userinfo_claims, true));
        $src = 0;
        foreach($tinfo['l'] as $key) {
            if(array_key_exists($key, $requested_userinfo_claims)) {
                $prefix = substr($key, 0, 3);
                if($prefix == 'ax.') {
                    $key = substr($key, 3);
                    $mapped_key = $key;
                    $kana = strpos($key, '_ja_kana_jp');
                    $hani = strpos($key, '_ja_hani_jp');
                    if($kana !== false)
                        $mapped_key = substr($key, 0, $kana) . '#ja-Kana-JP';
                    if($hani !== false)
                        $mapped_key = substr($key, 0, $hani) . '#ja-Hani-JP';
                    switch($mapped_key) {
                        case 'address' :
                            $userinfo[$mapped_key] = array(
                                'formatted' => $persona[$key]
                            );
                            break;

                        case 'email_verified' :
                        case 'phone_number_verified' :
                            if($persona[$key])
                                $userinfo[$mapped_key] = true;
                            else
                                $userinfo[$mapped_key] = false;
                            break;

                        default :
                            $userinfo[$mapped_key] = $persona[$key];
                            break;

                    }
                } elseif($prefix == 'cx.') {
                    $key = substr($key, 3);
                    $userinfo[$key] = $persona_claims[$key];
                }
            }
        }

        $sig_param = Array('alg' => 'none');
        $sig_key = NULL;
        if($db_client['userinfo_signed_response_alg']) {
            if(in_array($db_client['userinfo_signed_response_alg'], Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'))) {
                $sig_param['alg'] = $db_client['userinfo_signed_response_alg'];
                if(substr($db_client['userinfo_signed_response_alg'], 0, 2) == 'HS') {
                    $sig_key = $db_client['client_secret'];
                } elseif(substr($db_client['userinfo_signed_response_alg'], 0, 2) == 'RS') {
                    $sig_param['jku'] = OP_JWK_URL;
                    $sig_param['kid'] = OP_SIG_KID;
                    $sig_key = array('key_file' => OP_PKEY, 'password' => OP_PKEY_PASSPHRASE);
                }
                error_log("DistributedInfo Using Sig Alg {$sig_param['alg']}");
                $userinfo_jwt = jwt_sign($userinfo, $sig_param, $sig_key);
                if(!$userinfo_jwt) {
                    error_log("Unable to sign response for DistributedInfo");
                    send_bearer_error('400', 'invalid_request', 'Unable to sign response for DistributedInfo');
                }

                if($db_client['userinfo_encrypted_response_alg'] && $db_client['userinfo_encrypted_response_enc']) {
                    error_log("UserInfo Encryption Algs {$db_client['userinfo_encrypted_response_alg']} {$db_client['userinfo_encrypted_response_enc']}");
                    list($alg, $enc) = array($db_client['userinfo_encrypted_response_alg'], $db_client['userinfo_encrypted_response_enc']);
                    if(in_array($alg, Array('RSA1_5', 'RSA-OAEP')) && in_array($enc, Array('A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512'))) {
                        $jwk_uri = '';
                        $encryption_keys = NULL;
                        if($db_client['jwks_uri']) {
                            $jwk = get_url($db_client['jwks_uri']);
                            if($jwk) {
                                $jwk_uri = $db_client['jwks_uri'];
                                $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                                if(!$encryption_keys || !count($encryption_keys))
                                    $encryption_keys = NULL;
                            }
                        }
                        if(!$encryption_keys)
                            send_bearer_error('400', 'invalid_request', 'Unable to retrieve JWK key for encryption');
                        $userinfo_jwt = jwt_encrypt($userinfo_jwt, $encryption_keys[0], false, NULL, $jwk_uri, NULL, $alg, $enc, false);
                        if(!$userinfo_jwt) {
                            error_log("Unable to encrypt response for DistributedInfo");
                            send_bearer_error('400', 'invalid_request', 'Unable to encrypt response for DistributedInfo');
                        }

                    } else {
                        error_log("UserInfo Encryption Algs $alg and $enc not supported");
                        send_bearer_error('400', 'invalid_request', 'Client registered unsupported encryption algs for UserInfo');
                    }
                }

                header("Content-Type: application/jwt");
                header("Cache-Control: no-store");
                header("Pragma: no-cache");

                error_log('DistributedInfo response = ' . $userinfo_jwt);
                echo $userinfo_jwt;
            } else {
                error_log("UserInfo Sig Alg {$db_client['userinfo_signed_response_alg']} not supported");
                send_bearer_error('400', 'invalid_request', "UserInfo Sig Alg {$db_client['userinfo_signed_response_alg']} not supported");
            }
        } else {
            header("Cache-Control: no-store");
            header("Pragma: no-cache");
            header("Content-Type: application/json");
            error_log('DistributedInfo response = ' . json_encode($userinfo));
            echo json_encode($userinfo);
        }
    }
    catch(BearerException $e)
    {
        send_bearer_error('401', $e->error_code, $e->desc);

    }
    catch(OidcException $e)
    {
        send_error('', $e->error_code, $e->desc);
    }



}




function handle_login() {
    // check Proof of Posession (pop)
    $pop=0;
    $username=preg_replace('/[^\w=_@]/','_',$_POST['username']);
    if(db_check_credential($username,$_POST['password'])){
        $_SESSION['login']=1;
        $_SESSION['username']=$username;
        $_SESSION['persist']=$_POST['persist'];
        $_SESSION['auth_time'] = time();
        $_SESSION['ops'] = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        setcookie('ops', $_SESSION['ops'], 0, '/');
        setcookie('test', time(), 0);
        error_log("Auth_time = " . $_SESSION['auth_time']);
        $GET=$_SESSION['get'];
        error_log("session id = " . session_id());
        $display = $_SESSION['rpfA']['display'];
        error_log("prompt = " . $_SESSION['rpfA']['prompt']);
        $prompt = isset($_SESSION['rpfA']['prompt']) ? explode(' ', $_SESSION['rpfA']['prompt']) : array();
        $num_prompts = count($prompt);
        error_log("num prompt = {$num_prompts}" . print_r($prompt, true));
        if($num_prompts > 1 && in_array('none', $prompt)) {
            send_error($_REQUEST['redirect_uri'], 'interaction_required', "conflicting prompt parameters {$_SESSION['rpfA']['prompt']}", NULL, $_REQUEST['state']);
            exit();
        }
        if($num_prompts == 1 && in_array('none', $prompt))
            $showUI = false;
        else
            $showUI = true;        
        if(in_array('consent', $prompt)){
            echo confirm_userinfo($rpf);
            exit();
        }
        if(db_get_user_trusted_client($username, $_SESSION['rpfA']['client_id'])) {
            if(!$showUI)
                send_error($_REQUEST['redirect_uri'], 'interaction_required', "consent needed and prompt set to none", NULL, $_REQUEST['state']);
            echo confirm_userinfo($rpf);
        } else
            send_response($username, true);
//        if(!send_trusted_site_token()) {
//            if(!$showUI)
//                send_error($_REQUEST['redirect_uri'], 'interaction_required', "consent needed and prompt set to none", NULL, $_REQUEST['state']);
//            echo confirm_userinfo($rpf);
//        }
    } else { // Credential did not match so try again.
        echo loginform($_REQUEST['username_display'], $_REQUEST['username']);
    }
}


function handle_confirm_userinfo() {

    if(DEBUG) {
      echo "<pre>"; var_dump($_SESSION['rpfA']); echo "</pre>";
      echo "<pre>"; var_dump($_POST); echo "</pre>";
    }

    $GET=$_SESSION['get'];
    $rpfA=$_SESSION['rpfA'];
    $rpep=$GET['redirect_uri'];
    $atype = 'none';
    $client_id = $GET['client_id'];
    $response_types = explode(' ', $GET['response_type']);
    $scopes = explode(' ', $GET['scope']);
    $prompts = explode(' ', $GET['prompt']);

    $is_code_flow = in_array('code', $response_types);
    $is_token_flow = in_array('token', $response_types );
    $is_id_token = in_array('id_token', $response_types);
    
    $offline_access = $is_code_flow && !$is_token_flow && in_array('consent', $prompts) && in_array('offline_access', $scopes);

    $issue_at = strftime('%G-%m-%d %T');
    $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));
    error_log('Confirming UserInfo ' . print_r($_REQUEST, true));


    if($_REQUEST['confirm'] == 'confirmed') {
        $rpfA['session_id'] = session_id();
        $rpfA['auth_time'] = $_SESSION['auth_time'];
        if ($_REQUEST['agreed']=="1") {

            $attribs = array();
            $custom_claims = array();
            $confirmed_attribute_list = array();
            $policy_list = array();
            foreach($_POST as $key => $value) {
                if(strncasecmp($key, "conf_ax_", 8) == 0) {
                    array_push($confirmed_attribute_list, 'ax.' . substr($key, 8));
                    array_push($policy_list, 'ax.'. substr($key, 8));
                }else if(strncasecmp($key, "conf_cx_", 8) == 0) {
                    array_push($confirmed_attribute_list, 'cx.' . substr($key, 8));
                    array_push($policy_list, 'cx.' . substr($key, 8));
                } elseif(strncmp($key, 'ax_', 3) == 0) {
                    $attribs[substr($key, 3)] = $value;
                } elseif(strncmp($key, 'cx_', 3) == 0) {
                    $custom_claims[substr($key, 3)] = $value;
                }
            }
            db_save_user_persona($_SESSION['username'], $_POST['persona'], $attribs);
            db_save_user_persona_custom_claims($_SESSION['username'], $_POST['persona'], $custom_claims);

            if($is_code_flow) {
                $code_info = create_token_info($_SESSION['username'], $confirmed_attribute_list, $GET, $rpfA);
                $code = $code_info['name'];
                unset($code_info['name']);
                $fields = array('client' => $GET['client_id'],
                                'issued_at' => $issue_at,
                                'expiration_at' => $expiration_at,
                                'token' => $code,
                                'details' => $details_str,
                                'token_type' => TOKEN_TYPE_AUTH_CODE,
                                'info' => json_encode($code_info)
                               );
                db_save_user_token($_SESSION['username'], $code, $fields);
            }
            if($is_token_flow) {
                $code_info = create_token_info($_SESSION['username'], $confirmed_attribute_list, $GET, $rpfA);
                $token = $code_info['name'];
                unset($code_info['name']);
                $issue_at = strftime('%G-%m-%d %T');
                $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));
                $fields = array('client' => $GET['client_id'],
                                'issued_at' => $issue_at,
                                'expiration_at' => $expiration_at,
                                'token' => $token,
                                'details' => $details_str,
                                'token_type' => TOKEN_TYPE_ACCESS,
                                'info' => json_encode($code_info)
                               );
                db_save_user_token($_SESSION['username'], $token, $fields);
            }
            
            if($offline_access) {
                while(true) {
                        $refresh_token_name = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
                        if(!db_find_token($refresh_token_name))
                            break;
                }
                $fields = array('client' => $GET['client_id'],
                                'issued_at' => $issue_at,
                                'expiration_at' => $expiration_at,
                                'token' => $refresh_token_name,
                                'details' => $details_str,
                                'token_type' => TOKEN_TYPE_REFRESH,
                                'info' => json_encode($code_info)
                               );
                $fields['expiration_at'] = strftime('%G-%m-%d %T', time() + (24*60*60));
                db_save_user_token($_SESSION['username'], $refresh_token_name, $fields);
            }

            if($_REQUEST['trust'] == 'always') {
                error_log("Trust = Always for {$rpfA['client_id']}" . print_r($rpfA, true));
                $persona = db_get_user_persona($_SESSION['username'], $_POST['persona']);
                if($persona) {
                    db_save_user_site($_SESSION['username'], $rpfA['client_id'], array('url' => $rpfA['client_id'], 'persona_id' => $persona['id']));
                    $site = db_get_user_site($_SESSION['username'], $rpfA['client_id']);
                    if($site)
                        db_save_user_site_policies($_SESSION['username'], $rpfA['client_id'], $policy_list);
                }
            }
        } else {
            if($is_code_flow) {
                $code_info = create_token_info($_SESSION['username'], $confirmed_attribute_list, $GET, $rpfA);
                $code = $code_info['name'];
                unset($code_info['name']);
                $fields = array('client' => $GET['client_id'],
                                'issued_at' => $issue_at,
                                'expiration_at' => $expiration_at,
                                'token' => $code,
                                'details' => $details_str,
                                'token_type' => TOKEN_TYPE_AUTH_CODE,
                                'info' => json_encode($code_info)
                               );
                db_save_user_token($_SESSION['username'], $code, $fields);
            }
            if($is_token_flow) {
                $code_info = create_token_info($_SESSION['username'], $confirmed_attribute_list, $GET, $rpfA);
                $token = $code_info['name'];
                unset($code_info['name']);
                $fields = array('client' => $GET['client_id'],
                                'issued_at' => $issue_at,
                                'expiration_at' => $expiration_at,
                                'token' => $token,
                                'details' => $details_str,
                                'token_type' => TOKEN_TYPE_ACCESS,
                                'info' => json_encode($code_info)
                               );
                db_save_user_token($_SESSION['username'], $token, $fields);
            }
        }
    }
    else {
        $error = array( 
                        'error' => 'access_denied',
                        'error_description' => 'User declined request'
                      );
        if($rpfA['state'])
            $error['state'] = $rpfA['state'];
    }

    // TODO
    // Handle response_type for code or token
    if($error)
        $url = "$rpep?" . http_build_query($error);
    else {
        $fragments = Array();
        if($is_token_flow || $is_id_token) {
            $fragments[] = "access_token=$token";
            $fragments[] = 'token_type=Bearer';
            if($offline_access)
                $fragments[] = "refresh_token=$refresh_token_name";
            $fragments[] = 'expires_in=3600';
            if($GET['state'])
                $fragments[] = "state={$GET['state']}";
        }
        if($is_id_token) {
            $client_secret = NULL;
            $db_client = db_get_client($client_id);
            $sig_param = Array('alg' => 'none');
            $sig_key = NULL;
            if($db_client) {
                $client_secret = $db_client['client_secret'];
                if(!$db_client['id_token_signed_response_alg'])
                    $db_client['id_token_signed_response_alg'] = 'RS256';
                if(in_array($db_client['id_token_signed_response_alg'], Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'))) {
                    $sig_param['alg'] = $db_client['id_token_signed_response_alg'];
                    if(substr($db_client['id_token_signed_response_alg'], 0, 2) == 'HS') {
                        $sig_key = $db_client['client_secret'];
                    } elseif(substr($db_client['id_token_signed_response_alg'], 0, 2) == 'RS') {
                        $sig_param['jku'] = OP_JWK_URL;
                        $sig_param['kid'] = OP_SIG_KID;
                        $sig_key = array('key_file' => OP_PKEY, 'password' => OP_PKEY_PASSPHRASE);
                    }
                } else {
                    error_log("ID Token sig alg {{$db_client['id_token_signed_response_alg']} not supported");
                    send_bearer_error('400', 'invalid_request', "ID Token Sig Alg {$db_client['id_token_signed_response_alg']} not supported");
                }
            }

            error_log("ID Token Using Sig Alg {$sig_param['alg']}");
            $id_token_obj = array(
                                    'iss' => SERVER_ID,
                                    'sub' => wrap_userid($db_client, $_SESSION['username']),
                                    'aud' => array($client_id),
                                    'exp' => time() + 5*(60),
                                    'iat' => time(),
                                    'ops' => session_id() . '.' . $_SESSION['ops']
                                 );
            if($GET['nonce'])
                $id_token_obj['nonce'] = $GET['nonce'];
            error_log("userid = " . $id_token_obj['sub'] . ' unwrapped = ' . unwrap_userid($id_token_obj['sub']));                                 
                                 
            if(isset($rpfA['claims']) && isset($rpfA['claims']['id_token'])) {
                if(array_key_exists('auth_time', $rpfA['claims']['id_token']))
                    $id_token_obj['auth_time'] = (int) $_SESSION['auth_time'];
                    
                if(array_key_exists('acr', $rpfA['claims']['id_token'])) {
                    if(array_key_exists('values', $rpfA['claims']['id_token']['acr'])) {
                        if(is_array($rpfA['claims']['id_token']['acr']['values']) && count($rpfA['claims']['id_token']['acr']['values']))
                            $id_token_obj['acr'] = $rpfA['claims']['id_token']['acr']['values'][0];
                    } else
                        $id_token_obj['acr'] = '0';
                        
                }
            }
            if($sig_param['alg']) {
                $bit_length = substr($sig_param['alg'], 2);
                switch($bit_length) {
                    case '384':
                        $hash_alg = 'sha384';
                        break;
                    case '512':
                        $hash_alg = 'sha512';
                        break;                        
                    case '256':
                    default:
                        $hash_alg = 'sha256';
                    break;
                }
                $hash_length = (int) ((int) $bit_length / 2) / 8;
                if($code) {
                    error_log("************** got code");
                    $id_token_obj['c_hash'] = base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length));
                }
                if($token) {
                    error_log("************** got token");
                    $id_token_obj['at_hash'] = base64url_encode(substr(hash($hash_alg, $token, true), 0, $hash_length));
                }
                error_log("hash size = {$hash_length}");
            }

            $requested_id_token_claims = get_id_token_claims($rpfA);
            if($requested_id_token_claims) {
                $persona = db_get_user_persona($_SESSION['username'], $_POST['persona'])->toArray();
                $persona_custom_claims = db_get_user_persona_custom_claims($_SESSION['username'], $_POST['persona']);
                foreach($persona_custom_claims as $pcc) {
                    $persona_claims[$pcc['claim']] = $pcc->PersonaCustomClaim[0]['value'];
                }
                foreach($confirmed_attribute_list as $key) {
                    if(array_key_exists($key, $requested_id_token_claims)) {
                        $prefix = substr($key, 0, 3);
                        if($prefix == 'ax.') {
                            $key = substr($key, 3);
                            $mapped_key = $key;
                            $kana = strpos($key, '_ja_kana_jp');
                            $hani = strpos($key, '_ja_hani_jp');
                            if($kana !== false)
                                $mapped_key = substr($key, 0, $kana) . '#ja-Kana-JP';
                            if($hani !== false)
                                $mapped_key = substr($key, 0, $hani) . '#ja-Hani-JP';
                            switch($mapped_key) {
                                case 'address' :
                                    $id_token_obj[$mapped_key] = array(
                                                                        'formatted' => $persona[$key]
                                                                      );
                                    break;
                                
                                case 'email_verified' :
                                case 'phone_number_verified' :
                                    if($persona[$key])
                                        $id_token_obj[$mapped_key] = true;
                                    else
                                        $id_token_obj[$mapped_key] = false;
                                    break;
                                
                                default :
                                    $id_token_obj[$mapped_key] = $persona[$key];
                                    break;
                            }
                        } elseif($prefix == 'cx.') {
                            $key = substr($key, 3);
                            $id_token_obj[$key] = $persona_claims[$key];
                        }
                    }                    
                }
            }                                 
            $id_token = jwt_sign($id_token_obj, $sig_param, $sig_key);

            if(!$id_token) {
                error_log("Unable to sign response for ID Token");
                send_bearer_error('400', 'invalid_request', 'Unable to sign response for ID Token');
            }

            if($db_client['id_token_encrypted_response_alg'] && $db_client['id_token_encrypted_response_enc']) {
                error_log("ID Token Encryption Algs {$db_client['id_token_encrypted_response_alg']} {$db_client['id_token_encrypted_response_enc']}");
                list($alg, $enc) = array($db_client['id_token_encrypted_response_alg'], $db_client['id_token_encrypted_response_enc']);
                if(in_array($alg, Array('RSA1_5', 'RSA-OAEP')) && in_array($enc, Array('A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512'))) {
                    $jwk_uri = '';
                    $encryption_keys = NULL;
                    if($db_client['jwks_uri']) {
                        $jwk = get_url($db_client['jwks_uri']);
                        if($jwk) {
                            $jwk_uri = $db_client['jwks_uri'];
                            $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                            if(!$encryption_keys || !count($encryption_keys))
                                $encryption_keys = NULL;
                        }
                    }
                    if(!$encryption_keys)
                        send_bearer_error('400', 'invalid_request', 'Unable to retrieve JWK key for encryption');
                    $id_token = jwt_encrypt($id_token, $encryption_keys[0], false, NULL, $jwk_uri, NULL, $alg, $enc, false);
                    if(!$id_token) {
                        error_log("Unable to encrypt response for ID Token");
                        send_bearer_error('400', 'invalid_request', 'Unable to encrypt response for ID Token');
                    }

                } else {
                    error_log("ID Token Encryption Algs $alg and $enc not supported");
                    send_bearer_error('400', 'invalid_request', 'Client registered unsupported encryption algs for ID Token');
                }
            }

            $fragments[] = "id_token=$id_token";
        }
        $queries = Array();
        if($is_code_flow) {
            if(count($fragments) == 0) {
                $queries[] = "code=$code";
                if($GET['state'])
                    $queries[] = "state={$GET['state']}";
            } else {
                array_unshift($fragments, "code=$code");
            }
        }

        if(count($queries))
            $query = '?' . implode('&', $queries);
        if(count($fragments))
            $fragment = '#' . implode('&', $fragments);
        $url="$rpep{$query}{$fragment}";
    }
    if($_SESSION['persist']=='on') {
        $username = $_SESSION['username'];
        $auth_time = $_SESSION['auth_time'];
        $ops = $_SESSION['ops'];
        $login = $_SESSION['login'];
        clean_session();
        $_SESSION['lastlogin']=time();
        $_SESSION['username']=$username;
        $_SESSION['auth_time']=$auth_time;
        $_SESSION['ops'] = $ops;
        $_SESSION['login'] = $login;
        $_SESSION['persist']='on';
    } else {
        session_destroy();
    }
    error_log('redirect to ' . $url . "\n");
    header("Location:$url");
}

function handle_test() {
    $url = 'https://mgi1.gotdns.com:8443';
    $provider = db_get_provider_by_url($url);
    if($provider)
        preprint($provider->toArray());
}

function handle_file($file)
{
    echo file_get_contents($file);
}

function handle_default($file = null) {

if($file && file_exists(__DIR__ . $file)) {
    log_info("file = %s", __DIR__ . $file);
    echo file_get_contents(__DIR__ . $file);
    exit;
}

$error = $_REQUEST['error'];
$desc = $_REQUEST['description'];

if(!$error)
    $error_html = NULL;
else $error_html = <<<EOF
<p>Error : $error</p>
<p>Desc  : $desc</p>
EOF;

$server_name = OP_SERVER_NAME;

$html = <<<EOF
  <html>
  <head><title>$server_name OP</title>
  </head>
  <body style="background-color:#FFEEEE;">
  <h1>$server_name OP</h1>
  $error_html
  </body>
  </html>
EOF;

echo $html;

}


function check_redirect_uris($uris) {
    $valid = true;
    if($uris) {
        foreach($uris as $uri) {
            if(strpos($uri, '#') !== false) {
                $valid = false;
                break;
            }
        }
    } else
        $valid = false;
    return $valid;
}

function handle_client_registration() {
    $tmp_headers = apache_request_headers();
    foreach ($tmp_headers as $header => $value) {
        $headers[strtolower($header)] = $value;
    }
    if(!$headers['content-type'] || $headers['content-type'] != 'application/json') {
        echo print("unexpected content type");
        send_error(NULL, 'invalid_client_metadata', 'Unexpected content type');
    }
    $json = file_get_contents('php://input');
    error_log('Registration data ' . $json);
    if(!$json) {
        error_log('No JSON body in registration');
        send_error(NULL, 'invalid_client_metadata', 'No JSON body');
    }
    $data = json_decode($json, true);
    if(!$data) {
        error_log('Invalid JSON');
        send_error(NULL, 'invalid_client_metadata', 'Invalid JSON');
    }
    
    $keys = Array( 'contacts' => NULL,
                   'application_type' => NULL,
                   'client_name' => NULL,
                   'logo_uri' => NULL,
                   'redirect_uris' => NULL,
                   'token_endpoint_auth_method' => NULL,
                   'policy_uri' => NULL,
                   'tos_uri' => NULL,
                   'jwks_uri' => NULL,
                   'sector_identifier_uri' => NULL,
                   'subject_type' => NULL,
                   'request_object_signing_alg' => NULL,
                   'userinfo_signed_response_alg' => NULL,
                   'userinfo_encrypted_response_alg' => NULL,
                   'userinfo_encrypted_response_enc' => NULL,
                   'id_token_signed_response_alg' => NULL,
                   'id_token_encrypted_response_alg' => NULL,
                   'id_token_encrypted_response_enc' => NULL,
                   'default_max_age' => NULL,
                   'require_auth_time' => NULL,
                   'default_acr_values' => NULL,
                   'initiate_login_uri' => NULL,
                   'post_logout_redirect_uri' => NULL,
                   'request_uris' => NULL, 
                   'response_types' => NULL, 
                   'grant_types' => NULL, 
                   
                  );

    $client_id = base64url_encode(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
    $client_secret = base64url_encode(mcrypt_create_iv(10, MCRYPT_DEV_URANDOM));
    $reg_token = base64url_encode(mcrypt_create_iv(10, MCRYPT_DEV_URANDOM));
    $reg_client_uri_path = base64url_encode(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
    $params = Array(
                     'client_id' => $client_id,
                     'client_id_issued_at' => time(),                     
                     'client_secret' => $client_secret,
                     'client_secret_expires_at' => 0,
                     'registration_access_token' => $reg_token,
                     'registration_client_uri_path' => $reg_client_uri_path
                   );
    foreach($keys as $key => $default) {
        if(isset($data[$key])) {
            if(in_array($key, array('contacts', 'redirect_uris', 'request_uris', 'grant_types', 'response_types', 'default_acr_values')))
                $params[$key] = implode('|', $data[$key]);
            else
                $params[$key] = $data[$key];
        }
    }
    if(!check_redirect_uris($data['redirect_uris'])) {
        send_error(NULL, 'invalid_redirect_uri', 'redirect_uris is invalid');
    }
    if(isset($params['require_auth_time'])) {
         if($params['require_auth_time'])
            $params['require_auth_time'] = 1;
         else
            $params['require_auth_time'] = 0;
    }
    error_log("client registration params = " . print_r($params, true));
    db_save_client($client_id, $params);
    $reg_uri = OP_URL . '/client/' . $reg_client_uri_path;

    $client_json = Array(
                     'client_id' => $client_id,
                     'client_secret' => $client_secret,
                     'registration_access_token' => $reg_token,
                     'registration_client_uri' => $reg_uri,
                     'client_id_issued_at' => time(),
                     'client_secret_expires_at' => 0
                   );
    header("Cache-Control: no-store");
    header("Pragma: no-cache");
    header('Content-Type: application/json');
    $array_params = array('contacts', 'redirect_uris', 'request_uris', 'response_types', 'grant_types', 'default_acr_values');
    foreach($array_params as $aparam) {
        if(isset($params[$aparam]))
            $params[$aparam] = explode('|', $params[$aparam]);
    }
    if(isset($params['require_auth_time']))
        $params['require_auth_time'] = $params['require_auth_time'] == 1;
    echo json_encode(array_merge($client_json, $params));
}

function handle_client_operations() {
    // TODO test this part
    try
    {
        $token = $_REQUEST['access_token'];
        if(!$token) {
            $token = get_bearer_token();
            if(!$token)
                throw new BearerException('invalid_request', 'No Access Code');
        }

        $pos = strpos($_SERVER['PATH_INFO'], '/client/');
        if($pos === false)
            throw new OidcException('invailid_request', 'Invalid path');

        $uri_path = substr($_SERVER['PATH_INFO'], $pos + 8);
        $db_client = db_get_client_by_registration_uri_path($uri_path);
        if(!$db_client)
            throw new OidcException('invalid_request', 'Invalid client');
        if($db_client['registration_access_token'] != $token)
            throw new OidcException('invalid _request', 'Invalid registration token');
        $params = $db_client->toArray();

        unset($params['id']);
        unset($params['registration_access_token']);
        unset($params['registration_client_uri_path']);
        unset($params['jwk_encryption_uri']);
        unset($params['x509_uri']);
        unset($params['x509_encryption_uri']);
        $array_params = array('contacts', 'redirect_uris', 'request_uris', 'response_types', 'grant_types', 'default_acr_values');
        foreach($params as $key => $value) {
            if($value) {
                if(in_array($key, $array_params))
                    $params[$key] = explode('|', $value);
            } else
                unset($params[$key]);
        }
        if($params['require_auth_time'])
            $params['require_auth_time'] = $params['require_auth_time'] == 1;
        header("Cache-Control: no-store");
        header("Pragma: no-cache");
        header('Content-Type: application/json');
        echo pretty_json(json_encode($params));
    }
    catch(BearerException $e)
    {
        send_error(NULL, $e->error_code, $e->desc, NULL, true, '403');
    }
    catch(OidcException $e) {
        send_error(NULL, $e->error_code, $e->desc, NULL, true, '403');
    }

}

function wrap_userid($dbclient, $userid) {
    if($dbclient['subject_type'] == 'public')
        return $userid;
    else {  // generate pairwise
        $str = gzencode($dbclient['id'] . ':' . $userid, 9);
        error_log("zipped = " . bin2hex($str));

        $wrapped = bin2hex(aes_128_cbc_encrypt($str, '1234567890123456', '0101010101010101'));
        error_log("wrapped = " . $wrapped);
        return $wrapped;
    }
}

function unwrap_userid($userid) {
    $account = db_get_user($userid);
    if($account) {
        return $userid;
    } else {
        $str = pack("H*" , $userid);
        error_log("wrapped = " . $str);
        
        $wrapped_name = gzdecode(aes_128_cbc_decrypt($str, '1234567890123456', '0101010101010101'));
        error_log("unwrapped = " . $wrapped_name);
        $parts = explode(':', $wrapped_name);
        return $parts[1];
    }
    return NULL;
}


function handle_session_info() {
//    header('Content-Type: application/json');
//    $id_token = $_REQUEST['idtoken'];
//    $id_token = 'eyJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHBzOlwvXC9vcGVuaWQuZ290ZG5zLmNvbVwvYWJvcFwvb3AucGVtIn0.eyJpc3MiOiJodHRwczpcL1wvb3BlbmlkLmdvdGRucy5jb21cL2Fib3AiLCJ1c2VyX2lkIjoiYWxpY2UiLCJhdWQiOiJSTldyd0kzOFhBNnZpbzhuUWNtT3BRIiwiZXhwIjoxMzQzNjk2OTMwLCJpYXQiOjEzNDM2OTY2MzAsIm9wcyI6IjkyOWQ1MTcyZTQzMDE2OTRhOTJiYzlkMmE3MWE3MmMzLmM4N2I5YWU1MmM5NGE3ZWNiOWExNzk3NjE5Y2QwZmFhIiwibm9uY2UiOiJmMjNkNzU5YzkyZGM0MTNkNzE3MzU2OTM3NmE1YmE4MCIsImNfaGFzaCI6Ilh4SUxtVjZWdGpySzNabTJSZXB1LWcifQ.Bd_p1DaE7g4S6SPFiiFEeH1RdwVHZDHK8ch9iFPk4x8VRXJiprgLEXJDfMFCO-C6xUjViTG6A9fRIjbxDveNBR8M88QQc1IPFChH6ZguHZiS_DoeWVCjtv7QjeBchT-fz3HifpG6yWeLHT84bjfnrpL7-lPJjmfuD9lEsjJSTio';
//    error_log("id_token = {$id_token}");
//    
//    list($header, $payload, $sig) = jwt_to_array($id_token);
//    $client_id = $payload['aud'];
//    if(!$client_id) {
//        error_log("handle_session_info missing client_id");
//        exit;
//    }
//    $client = db_get_client($client_id);
//    if(!$client) {
//        error_log("handle_session_info invalid client_id");
//        exit;
//    }
//
//    if(substr($header['alg'], 0, 2) == 'HS') {
//        $verified = jwt_verify($id_token, $client['client_secret']);
//    } elseif(substr($header['alg'], 0, 2) == 'RS') {
//        $pub = file_get_contents(OP_PCERT);
//        $verified = jwt_verify($id_token, $pub);
//    } elseif($header['alg'] == 'none')
//        $verified = true;
//        
//    error_log("{$header['alg']} Signature Verification = $verified");
//    if(!$verified) {
//        error_log('idtoken sig failed');
//        exit;
//    }
//
//    error_log("id token payload = " . print_r($payload, true));
//
//    $ops_str = $payload['ops'];
//    if(!$ops_str) {
//        error_log('no ops string');
//        exit;
//    }
//    
//    $res = array();
//    $index = strrpos($ops_str, '.');
//    if($index !== false) {
//        $session_id = substr($ops_str, 0, $index);
//        $ops = substr($ops_str, $index+1);
//        error_log("session id = {$session_id} ops = {$ops}");
//        if(!$session_id || !$ops) {
//            error_log('invalid session id or ops');
//            exit;
//        }
////        session_id($session_id);
//        if(session_start()) {
//            error_log('session = ' . print_r($_SESSION, true));
//            if($_SESSION['username'] && $_SESSION['login']) {
//                $res = array(
//                              'sessionid' => $session_id,
//                              'ops' => $_SESSION['ops']
//                            );
//                if($_SESSION['ops'] != $ops)
//                    error_log("ops changed from {$ops} to {$_SESSION['ops']}");
//                else
//                    error_log("ops {$ops} unchanged");
//            } else {
//                error_log('session info user no longer logged in');
//            }
//        } else {
//            error_log('Unable to start session');
//        }
//    } else {
//        error_log('invalid ops string');
//    }
//    echo json_encode($res);

error_log("cookie = " . print_r($_COOKIE, true));


    header('Content-Type: application/json');
    setcookie('mycookie', 'hello', 0, '/');
    $res = array();
    if(session_start()) {
        error_log('session = ' . print_r($_SESSION, true));
        if($_SESSION['username'] && $_SESSION['login']) {
            $res = array(
                          'ops' => session_id() . '.' . $_SESSION['ops']
                        );
        } else {
            error_log('session info user no longer logged in ' . print_r(_SESSION, true));
        }
    } else {
        error_log('Unable to start session');
    }
    echo json_encode($res);
}


function make_id_token($username, $issuer, $aud, $claims = array(), $nonce = NULL, $code_hash = NULL, $token_hash = NULL, $auth_time = NULL, $ops = NULL, $acr = NULL)
{
    $id_token_obj = array(
        'iss' => $issuer,
        'sub' => $username,
        'aud' => array($aud),
        'exp' => time() + 5*(60),
        'iat' => time()
    );

    if(isset($nonce))
        $id_token_obj['nonce'] = $nonce;
    if(isset($code_hash))
        $id_token_obj['c_hash'] = $code_hash;
    if(isset($token_hash))
        $id_token_obj['at_hash'] = $token_hash;
    if(isset($ops))
        $id_token_obj['ops'] = $ops;
    if(isset($auth_time))
        $id_token_obj['auth_time'] = $auth_time;
    if(isset($acr))
        $id_token_obj['acr'] = $acr;
    foreach($claims as $k => $v) {
        $id_token_obj[$k] = $v;
    }
    return $id_token_obj;
}


function get_account_claims($db_user, $requested_claims)
{
    $claims = array();
    log_debug("account requested claims = %s", print_r($requested_claims, true));
    foreach($requested_claims as $key => $value) {
        $mapped_key = $key;
        $kana = strpos($key, '_ja_kana_jp');
        $hani = strpos($key, '_ja_hani_jp');
        if($kana !== false)
            $mapped_key = substr($key, 0, $kana) . '#ja-Kana-JP';
        if($hani !== false)
            $mapped_key = substr($key, 0, $hani) . '#ja-Hani-JP';
        switch($mapped_key) {
            case 'address' :
                $claims[$mapped_key] = array(
                    'formatted' => $db_user[$key]
                );
                break;

            case 'email_verified' :
            case 'phone_number_verified' :
                if(isset($db_user[$key]))
                    $claims[$mapped_key] = true;
                else
                    $claims[$mapped_key] = false;
                break;

            default :
                $claims[$mapped_key] = $db_user[$key];
                break;
        }
    }
    log_debug('returning = %s', print_r($claims, true));
    return $claims;
}

function send_response($username, $authorize = false)
{
    $GET=$_SESSION['get'];
    $rpfA=$_SESSION['rpfA'];
    $rpep=$GET['redirect_uri'];
    $state = isset($GET['state']) ? $GET['state'] : NULL;
    $error_page = isset($GET['redirect_uri']) ? $GET['redirect_uri'] : OP_INDEX_PAGE;

    try
    {
        $client_id = $GET['client_id'];
        $response_types = explode(' ', $GET['response_type']);
        $scopes = explode(' ', $GET['scope']);
        $prompts = explode(' ', $GET['prompt']);

        $is_code_flow = in_array('code', $response_types);
        $is_token_flow = in_array('token', $response_types );
        $is_id_token = in_array('id_token', $response_types);

        $offline_access = $is_code_flow && !$is_token_flow && in_array('consent', $prompts) && in_array('offline_access', $scopes);

        $issue_at = strftime('%G-%m-%d %T');
        $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));

        if(!$authorize)
            throw new OidcException('access_denied', 'User denied access');

        $rpfA['session_id'] = session_id();
        $rpfA['auth_time'] = $_SESSION['auth_time'];
        $confirmed_attribute_list = get_all_requested_claims($rpfA, $GET['scope']);

        if($is_code_flow) {
            $code_info = create_token_info($username, $confirmed_attribute_list, $GET, $rpfA);
            $code = $code_info['name'];
            unset($code_info['name']);
            $fields = array('client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $code,
                'details' => '',
                'token_type' => TOKEN_TYPE_AUTH_CODE,
                'info' => json_encode($code_info)
            );
            db_save_user_token($username, $code, $fields);
        }
        if($is_token_flow) {
            $code_info = create_token_info($username, $confirmed_attribute_list, $GET, $rpfA);
            $token = $code_info['name'];
            unset($code_info['name']);
            $issue_at = strftime('%G-%m-%d %T');
            $expiration_at = strftime('%G-%m-%d %T', time() + (2*60));
            $fields = array('client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $token,
                'details' => '',
                'token_type' => TOKEN_TYPE_ACCESS,
                'info' => json_encode($code_info)
            );
            db_save_user_token($username, $token, $fields);
        }

        if($offline_access) {
            while(true) {
                $refresh_token_name = base64url_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
                if(!db_find_token($refresh_token_name))
                    break;
            }
            $fields = array('client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $refresh_token_name,
                'details' => '',
                'token_type' => TOKEN_TYPE_REFRESH,
                'info' => json_encode($code_info)
            );
            $fields['expiration_at'] = strftime('%G-%m-%d %T', time() + (24*60*60));
            db_save_user_token($username, $refresh_token_name, $fields);
        }

        // Handle response_type for code or token

        $fragments = Array();
        if($is_token_flow || $is_id_token) {
            $fragments[] = "access_token=$token";
            $fragments[] = 'token_type=Bearer';
            if($offline_access)
                $fragments[] = "refresh_token=$refresh_token_name";
            $fragments[] = 'expires_in=3600';
            if($GET['state'])
                $fragments[] = "state={$GET['state']}";
        }
        if($is_id_token) {

            $client_secret = null;
            $nonce = isset($GET['nonce']) ? $GET['nonce'] : null;
            $c_hash = null;
            $at_hash = null;
            $ops = null;
            $auth_time = null;
            $acr = null;
            $idt_claims = array();
            $sig = null;
            $alg = null;
            $enc = null;
            $client_secret = null;
            $jwk_uri = null;
            $db_client = db_get_client($client_id);
            if($db_client) {
                $sig = $db_client['id_token_signed_response_alg'];
                if(!isset($sig))
                    $sig = 'RS256';
                $alg = $db_client['id_token_encrypted_response_alg'];
                $enc = $db_client['id_token_encrypted_response_enc'];
                $client_secret = $db_client['client_secret'];
                $jwk_uri = $db_client['jwks_uri'];
            }

            if(isset($rpfA['claims']) && isset($rpfA['claims']['id_token'])) {
                if(array_key_exists('auth_time', $rpfA['claims']['id_token']))
                    $auth_time = (int) $_SESSION['auth_time'];

                if(array_key_exists('acr', $rpfA['claims']['id_token'])) {
                    if(array_key_exists('values', $rpfA['claims']['id_token']['acr'])) {
                        if(is_array($rpfA['claims']['id_token']['acr']['values']) && count($rpfA['claims']['id_token']['acr']['values']))
                            $acr = $rpfA['claims']['id_token']['acr']['values'][0];
                    } else
                        $acr = '0';
                }
            }
            if($sig) {
                $bit_length = substr($sig, 2);
                switch($bit_length) {
                    case '384':
                        $hash_alg = 'sha384';
                        break;
                    case '512':
                        $hash_alg = 'sha512';
                        break;
                    case '256':
                    default:
                        $hash_alg = 'sha256';
                        break;
                }
                $hash_length = (int) ((int) $bit_length / 2) / 8;
                if($code)
                    $c_hash = base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length));
                if($token)
                    $at_hash = base64url_encode(substr(hash($hash_alg, $token, true), 0, $hash_length));
            }
            $requested_id_token_claims = get_id_token_claims($rpfA);
            if($requested_id_token_claims) {
                $db_user = db_get_user($username);
                if($db_user)
                    $idt_claims = get_account_claims($db_user, $requested_id_token_claims);
                else
                    throw new OidcException('access_denied', 'no such user');
            }
            $id_token_obj = make_id_token(wrap_userid($db_client, $username), SERVER_ID, $client_id, $idt_claims, $nonce, $c_hash, $at_hash, $auth_time, $ops, $acr );

            log_debug('sen_response id_token_obj = %s', print_r($id_token_obj));
            $cryptoError = null;
            $id_token = sign_encrypt($id_token_obj, $sig, $alg, $enc, $jwk_uri, $client_secret, $cryptoError);

            if(!$id_token) {
                log_error("Unable to sign encrypt response for ID Token {$cryptoError}");
                throw new OidcException('invalid_request', "idtoken crypto error {$cryptoError}");
            }
            $fragments[] = "id_token=$id_token";
        }
        $queries = Array();
        if($is_code_flow) {
            if(count($fragments) == 0) {
                $queries[] = "code=$code";
                if($GET['state'])
                    $queries[] = "state={$GET['state']}";
            } else {
                array_unshift($fragments, "code=$code");
            }
        }

        if(count($queries))
            $query = '?' . implode('&', $queries);
        if(count($fragments))
            $fragment = '#' . implode('&', $fragments);
        $url="$rpep{$query}{$fragment}";

        if($_SESSION['persist']=='on') {
            $username = $_SESSION['username'];
            $auth_time = $_SESSION['auth_time'];
            $ops = $_SESSION['ops'];
            $login = $_SESSION['login'];
            clean_session();
            $_SESSION['lastlogin']=time();
            $_SESSION['username']=$username;
            $_SESSION['auth_time']=$auth_time;
            $_SESSION['ops'] = $ops;
            $_SESSION['login'] = $login;
            $_SESSION['persist']='on';
        } else {
            session_destroy();
        }
        log_debug('redirect to %s', $url);
        header("Location:$url");
    }
    catch(OidcException $e) {
        log_error("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, $e->error_code, $e->desc, NULL, $state);
    }
    catch(Exception $e) {
        log_error("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, 'invalid_request', $e->getMessage(), NULL, $state);
    }

}

function sign_encrypt($payload, $sig, $alg, $enc, $jwks_uri = null, $client_secret = null, &$cryptoError = null)
{
    log_debug("sign_encrypt sig = %s alg = %s enc = %s", $sig, $alg, $enc);
    $jwt = is_array($payload) ? json_encode($payload) : $payload;

    if(isset($sig)) {
        $sig_param = Array('alg' => 'none');
        $sig_key = NULL;
        if(in_array($sig, Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'))) {
            $sig_param['alg'] = $sig;
            if(substr($sig, 0, 2) == 'HS') {
                $sig_key = $client_secret;
            } elseif(substr($sig, 0, 2) == 'RS') {
                $sig_param['kid'] = OP_SIG_KID;
                $sig_key = array('key_file' => OP_PKEY, 'password' => OP_PKEY_PASSPHRASE);
            }
        } else {
            log_error("sig alg {$sig} not supported");
            if($cryptoError)
                $cryptoError = 'error_sig';
            return null;
        }
        $jwt = jwt_sign($jwt, $sig_param, $sig_key);
        if(!$jwt) {
            if($cryptoError)
                $cryptoError = 'error_sig';
            log_error("Unable to sign payload {$jwt}");
            return null;
        }

        log_debug('jws = %s', $jwt);
    }

    if(isset($alg) && isset($enc)) {
        if(in_array($alg, Array('RSA1_5', 'RSA-OAEP')) && in_array($enc, Array('A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512'))) {
            $jwk_uri = '';
            $encryption_keys = NULL;
            if($jwks_uri) {
                $jwk = get_url($jwks_uri);
                if($jwk) {
                    $jwk_uri = $jwks_uri;
                    $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                    if(!$encryption_keys || !count($encryption_keys))
                        $encryption_keys = NULL;
                }
            }
            if(!$encryption_keys) {
                if($cryptoError)
                    $cryptoError = 'error_enc';
                log_error("Unable to get enc keys");
                return null;
            }
            $jwt = jwt_encrypt($jwt, $encryption_keys[0], false, NULL, $jwk_uri, NULL, $alg, $enc, false);
            if(!$jwt) {
                if($cryptoError)
                    $cryptoError = 'error_enc';
                log_error("Unable to encrypt {jwt}");
                return null;
            }
            log_debug('jwe = %s', $jwt);

        } else {
            $cryptoError  = 'error_enc';
            log_error("encryption algs not supported {$alg} {$enc}");
            return null;
        }
    }
    return $jwt;
}
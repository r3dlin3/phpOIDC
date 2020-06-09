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

include_once("../config.php");
include_once("../libjsoncrypto.php");
include_once('../libdb2.php');
include_once('../logging.php');
include_once('../OidcException.php');
include_once('../apache_header.php');
include_once('../Mailer.php');

error_reporting(E_ERROR | E_WARNING | E_PARSE);
//error_reporting(E_ALL);

define("DEBUG", 0);

define("TOKEN_TYPE_AUTH_CODE", 0);
define("TOKEN_TYPE_ACCESS",    1);
define("TOKEN_TYPE_REFRESH",   2);


header('Content-Type: text/html; charset=utf8');

// $session_path = session_save_path() . OP_PATH;
// if(!file_exists($session_path))
//     mkdir($session_path);
// session_save_path($session_path);
session_set_cookie_params(0, OP_PATH);
// NOTE: null or empty string is causing issue with the switch case & preg_match
$path_info = array_key_exists('PATH_INFO', $_SERVER) ? $_SERVER['PATH_INFO'] : "/";
switch ($path_info) {
    case '/token':
    case '/validatetoken':
    case '/userinfo':
    case '/distributedinfo':
    case '/registration':
    case '/sessioninfo':
    case '/client':
        break;

    default:
        session_start();
        break;
}


logw_debug("Request: %s\nInput: %s\nSession:%s", count($_REQUEST) ? print_r($_REQUEST, true) : 'req[ ]', file_get_contents('php://input'), isset($_SESSION) ? print_r($_SESSION, true) : 'sess[ ]');


switch ($path_info) {
    case '/token':
        handle_token();
        break;
    case '/validatetoken':
        handle_validatetoken();
        break;
    case '/userinfo':
        handle_userinfo();
        break;
    case '/distributedinfo':
        handle_distributedinfo();
        break;
    case '/registration':
        handle_client_registration();
        break;
    case '/sessioninfo':
        break;
    case '/client':
        break;
    case '/login':
        handle_login();
        break;
    case '/oplogin':
        echo loginform('', '', null, true);
        break;
    case '/confirm_userinfo':
        handle_confirm_userinfo();
        break;
    case '/endsession':
        handle_end_session();
        break;
    case '/logout':
        handle_logout();
        break;
    case '/auth':
        handle_auth();
        break;
    case '/register_form':
        handle_register_form();
        break;
    case '/register':
        handle_register();
        break;
    case '/register_continue':
        handle_register_continue();
        break;
    case '/forgotpassword_form':
        handle_forgotpassword_form();
        break;
    case '/forgotpassword':
        handle_forgotpassword();
        break;
    case (preg_match('/\/passwordreset\/(.*)\/(.*)/', $path_info, $matches) ? true : false):
        handle_passwordreset_code($matches[1], $matches[2]);
        break;
    case (preg_match('/\/socialite\/(.*)/', $path_info, $matches) ? true : false):
        handle_socialite($matches[1]);
        break;
    case (preg_match('/\/socialitecb\/(.*)\/+/', $path_info, $matches) ? true : false):
        handle_socialite_callback($matches[1]);
        break;
    case '/passwordreset':
        handle_passwordreset();
        break;
    case (preg_match('/\/client.*/', $path_info) ? true : false):
        handle_client_operations();
        break;
    default:
        handle_default($path_info);
}

exit();


/**
 * Will display an error screen if a functionality is not enabled
 */
function check_functionality($flag, $display_name = null)
{
    global $blade;
    global $config;

    if (empty($display_name)) {
        // Compute display_name if empty
        // ex: 'enable_password_reset' => 'Password reset'
        $display_name = str_replace('_','',ucwords(str_replace('enable_','', $flag)));
    }

    if (!$config['site'][$flag]) {
        $str = $blade->run('error', [
            'error' => "Functionality is disabled",
            'desc' => "$display_name is disabled.",
        ]);
        echo $str;
        exit;
    }
}

function handle_socialite_callback($provider)
{
    try  {
        check_functionality('enable_social_login');
        global $config;
        $provider = Laravel\Socialite\SocialiteManager::driver($provider, $config['socialite']);
        $authenticated_user = $provider->user();

        $account = db_get_account($authenticated_user->getLogin());
        if($account) {
            // account already exists
            $need_update = false;
            foreach($authenticated_user as $key=>$val) {
                if (isset($val) && $account[$key] !== $val) {
                    $account[$key] = $val;
                    $need_update = true;
                }
            }
            if ($need_update) {
                db_save_account($account);
            }
        } else {
            $account = db_create_account($authenticated_user);
        }
    } catch (Exception $e) {
        log_error("handle_socialite_callback exception : %s", $e->getTraceAsString());
        $error_page = array_key_exists('redirect_uri', $_SESSION['rpfA']) ? $_SESSION['rpfA']['redirect_uri'] : OP_INDEX_PAGE;
        $state = array_key_exists('state', $_SESSION['rpfA']) ? $_SESSION['rpfA']['state'] : NULL;
        $response_mode =  get_response_mode($_SESSION['rpfA']);
        send_error($error_page, 'invalid_request', $e->getMessage(), NULL, $state, $response_mode);
    }

    after_authentication($account->getLogin(), 'on');
}

/**
 * Will send an authentication request to the provider
 * @param string provider Provider name (google, linkedin, etc.)
 */
function handle_socialite($provider) 
{
    check_functionality('enable_social_login');

    global $config;
    $provider = Laravel\Socialite\SocialiteManager::driver($provider, $config['socialite']);
    $url = $provider->redirect();
    log_debug('Redirect to %s', $url);
    header("Location: $url");
    exit;
}


/**
 * Show Login form.
 * @return String HTML Login form.
 */
function loginform($display_name = '', $user_id = '', $client = null, $oplogin = false, $error = false)
{
    global $blade;
    global $config;
    $login_handler = $oplogin ? 'op' : '';

    $socialite = $config['site']['enable_social_login'] ? array_map(function ($a) { return $a['enable']; }, $config['socialite']) : [];

    $action_url = $_SERVER['SCRIPT_NAME'] . '/' . $login_handler . 'login';
    $str = $blade->run('login', [
        'display_name' => $display_name,
        'user_id' => $user_id,
        'client' => $client,
        'action_url' => $action_url,
        'error' => $error,
        'enable_social_login' => $config['site']['enable_social_login'],
        'socialite' => $socialite
    ]);
    return $str;
}

function handle_register_continue()
{
    echo loginform(
        $_SESSION['user']['display_name'],
        $_SESSION['user']['username'],
        $_SESSION['client']
    );
    exit();
}

function handle_register_form()
{
    global $blade;
    global $config;
    global $register_form;

    if (!$config['site']['enable_registration']) {
        $str = $blade->run('error', [
            'error' => "Functionality is disabled",
            'desc' => "Registration is disabled.",
        ]);
        echo $str;
        return;
    }

    $str = $blade->run('register', [
        'form' => $register_form,
        'action_url' => OP_REGISTRATION_EP,
        'login_url' => OP_LOGIN_EP,
    ]);
    echo $str;
}

function handle_forgotpassword_form($error = false)
{
    global $blade;
    global $config;

    check_functionality('enable_password_reset');

    $str = $blade->run('forgotpassword', [
        'action_url' => OP_PASSWORD_RESET_CONTINUE_EP,
        'login_url' => OP_LOGIN_EP,
        'error' => $error
    ]);
    echo $str;
}

/**
 * Generate a random-ish code
 * @return string random string
 */
function generate_password_reset_code($length = 80)
{
    $code = substr(bin2hex(openssl_random_pseudo_bytes($length)), 0, $length);
    return $code;
}



/**
 * Function for basic field validation (present and neither empty nor only white space)
 * cf. https://stackoverflow.com/a/381275
 */
function isNullOrEmptyString($str)
{
    return (!isset($str) || trim($str) === '');
}


/**
 * Check the given code against he value in the database
 *
 * @param string $resetCode Reset code from the database
 * @param string $resetCodeTimeout Max datetime for the code
 * @param string $input the code to check
 * @return boolean Pass/fail of verification
 */
function check_reset_password_code($resetCode, $resetCodeTimeout, $input)
{

    if (isNullOrEmptyString($resetCode)) {
        log_error("reset code is null or empty in database");
        return false;
    }
    if (isNullOrEmptyString($input)) {
        log_error("input for reset code is null or empty in database");
        return false;
    }

    // Verify the timeout
    if ($resetCodeTimeout < new \DateTime()) {
        log_error("Reset code has timeout");
        return false;
    }

    // We made it this far, compare the hashes
    $result = hash_equals($resetCode, $input);
    return $result;
}

function handle_passwordreset()
{
    global $blade;
    global $config;

    check_functionality('enable_password_reset');
    if (
        !array_key_exists('user', $_SESSION)
        || !array_key_exists('id', $_SESSION['user'])
        || empty($_SESSION['user']['id'])
    ) {
        if (!$config['site']['enable_password_reset']) {
            $str = $blade->run('error', [
                'error' => "Invalid code",
                'desc' => "Password reset code is invalid.",
            ]);
            echo $str;
            exit;
        }
    }
    $account_id = $_SESSION['user']['id'];
    // TODO: validate password complexity
    $res = db_save_account_by_id($account_id, [
        'crypted_password' => create_hash($_POST['password']),
        'reset_password_code' => '',
        'reset_password_code_timeout' => null
    ]);

    if ($res) {
        $str = $blade->run('reset_success', [
            'next_url' => OP_LOGIN_EP
        ]);
    } else {
        $str = $blade->run('error', [
            'error' => "Something went wrong",
            'desc' => "Could not save the password",
        ]);
    }
    echo $str;
    return;
}

/**
 * Check the password reset code. Display the form for the new password.
 */
function handle_passwordreset_code($code, $email)
{
    global $blade;
    global $config;
    check_functionality('enable_password_reset');

    $email = base64_decode($email);

    $account = db_get_account_by_email($email);
    if ($account) {
        if (check_reset_password_code($account->getResetPasswordCode(), $account->getResetPasswordCodeTimeout(), $code)) {
            $res = db_save_account_by_id($account->getId(), [
                'reset_password_code' => '',
                'reset_password_code_timeout' => null
            ]);
            if ($res) {
                $_SESSION['user'] = [
                    'id' => $account->getId(),
                    'username' => $account->getLogin(),
                    'display_name' => $account->getName()
                ];

                $str = $blade->run('reset', [
                    'action_url' => OP_PASSWORD_RESET_CODE_CONTINUE_EP,
                ]);
                echo $str;
                return;
            } else {
                $str = $blade->run('reset', [
                    'error' => "Password reset",
                    'desc' => "Code is invalid.",
                ]);
                echo $str;
                return;
            }
        }
    }
    
    $str = $blade->run('error', [
        'error' => "Password reset",
        'desc' => "Code is invalid or expired. Try to reset your password again.",
    ]);
    echo $str;
    return;
}

function handle_forgotpassword()
{
    global $blade;
    global $config;

    check_functionality('enable_password_reset');
    $email = urldecode(trim($_POST['email']));

    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        handle_forgotpassword_form(true);
        return;
    }

    $account = db_get_account_by_email($email);
    if ($account) {
        $code = generate_password_reset_code();
        $res = db_save_account_by_id($account->getId(), [
            'reset_password_code' => $code,
            'reset_password_code_timeout' => new \Datetime('+1 hour')
        ]);
        if (!$res) {
            log_error("Could not save password reset code for %s", $email);
            $str = $blade->run('error', [
                'error' => "Something went wrong",
                'desc' => "Could not save your account",
            ]);
            echo $str;
            return;
        }

        $url = OP_PASSWORD_RESET_CODE_EP . urlencode($code) . '/' . base64_encode($email);
        $mail_body = $blade->run('emails.forgotpassword', [
            'url' => $url,
        ]);
        $mail_subject = $blade->_ef('Password reset for %s', $config['site']['name']);
        $mailer = new Mailer($config['mail']);
        $mailer->mail($email, $mail_subject, $mail_body);
        log_info("Password reset mail sent to %s", $email);
    }

    // Ignore use case when user isn't found. Return a success in any case
    // We don't want to reveal that someone has an email in our database
    $view = $blade->run('forgotpassword_success', [
        "site" => $config['site'] // as this is the second time we use blade, the shared "site"
                                  // variable is not set anymore...
    ]);
    echo $view;
}

function get_value_from_form_by_property_name($form, $name)
{
    $row = array_filter($form, function ($k) use ($name) {
        return $k['name'] == $name;
    });
    if ($row && count($row) == 1) {
        $tmp = array_pop($row);
        return $tmp['value'];
    }
    return null;
}

/**
 * Validate form data used by the registration page
 */
function validate_register_data(&$form)
{
    $validaton_status = true;

    foreach ($form as &$item) {
        $name = $item['name'];
        $val = array_key_exists($name, $_POST) ? trim($_POST[$name]) : null;
        $rules = array_key_exists('rules', $item) ? $item['rules'] : [];
        if ($item['type'] === 'computed') {
            if (
                array_key_exists('equalTo', $rules)
                && !empty($rules['equalTo'])
            ) {
                $equal_to_property_name = $rules['equalTo'];
                $item['value'] = get_value_from_form_by_property_name($form, $equal_to_property_name);
            } elseif (
                array_key_exists('join', $rules)
                && !empty($rules['join'] && is_array($rules['join']))
            ) {
                $values = [];
                foreach ($rules['join'] as $propname) {
                    // push value
                    $values[] = get_value_from_form_by_property_name($form, $propname);
                }
                $item['value'] = join(' ', $values);
            }
        } else {
            $item['value'] = $val;
            if ($item['type'] === 'email') {
                if (!filter_var($val, FILTER_VALIDATE_EMAIL)) {
                    $item['error_message'] = $item['message'];
                }
            }
            if (array_key_exists('required', $rules) && $rules['required']) {
                if (empty($val)) {
                    $item['error_message'] = $item['message'];
                }
            }
            if (array_key_exists('minlength', $rules)) {
                if (strlen($val) < $rules['minlength']) {
                    $item['error_message'] = $item['message'];
                }
            }
            if (array_key_exists('maxlength', $rules)) {
                if (strlen($val) > $rules['maxlength']) {
                    $item['error_message'] = $item['message'];
                }
            }
            // TODO: validate password complexity
            if (array_key_exists('error_message', $item)) {
                $validaton_status = false;
            }
        }
    }
    return $validaton_status;
}
/**
 * Convert data to an associative array
 * + convert password
 * @return username
 */
function prepare_register_data($form)
{
    $values = [];
    foreach ($form as $property) {
        if ($property['type'] === 'password') {
            $values['crypted_password'] = create_hash($property['value']);
        } else {
            $values[$property['name']] = $property['value'];
        }
    }
    return $values;
}

function handle_register()
{
    global $blade;
    global $register_form;
    global $config;

    if (!$config['site']['enable_registration']) {
        $str = $blade->run('error', [
            'error' => "Functionality is disabled",
            'desc' => "Registration is disabled.",
        ]);
        echo $str;
        return;
    }
    if (!validate_register_data($register_form)) {
        handle_register_form();
        return;
    }
    $values = prepare_register_data($register_form);
    if (db_create_account_with_values($values['login'], $values)) {
        $_SESSION["user"] = [
            "username" => $values['login'],
            "display_name" => $values['name'],
        ];
        $str = $blade->run('register_success', [
            'next_url' => OP_REGISTRATION_CONTINUE_EP,
        ]);
        echo $str;
    } else {
        $str = $blade->run('error', [
            'error' => "Something went wrong",
            'desc' => "Could not save your account",
        ]);
        echo $str;
    }
}

/**
 * Show Confirmation Dialogue for Attributes.
 * @param  String $r     Request String (JSON)
 * @return String HTML to be shown.
 */
function confirm_userinfo()
{
    global $blade;
    $req = $_SESSION['rpfA'];
    $scopes = explode(' ', $req['scope']);
    $response_types = explode(' ', $req['response_type']);

    // Remove offline_access scope if it will not be issued
    if (in_array('offline_access', $scopes) && in_array('code', $response_types)) {
        $key = array_search('offline_access', $scopes);
        unset($scopes[$key]);
    }

    $client = $_SESSION['client'];

    $requested_claims = get_all_requested_claims($req, $req['scope']);
    log_info('requested claims = %s', print_r($requested_claims, true));

    $account = db_get_account($_SESSION['username']);
    $action_url = $_SERVER['SCRIPT_NAME'] . '/confirm_userinfo';

    $str = $blade->run('consent', [
        'display_name' => "",
        'user_id' => "",
        'scopes' => $scopes,
        'account' => $account,
        'action_url' => $action_url,
        'client' => $client
    ]);
    return $str;
}



function create_token_info($uname, $attribute_list = NULL, $get = NULL, $req = NULL)
{
    while (true) {
        $token_name = base64url_encode(random_bytes(32));
        if (!db_find_token($token_name))
            break;
    }
    $arr = array();
    $arr['name'] = $token_name;
    $expires_in = 60; //in seconds
    $arr['e'] = time() + $expires_in;
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
function get_url($url)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $responseText = curl_exec($ch);
    $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($http_status != 200) {
        if ($responseText && substr($url, 0, 7) == 'file://')
            return $responseText;
        log_error("Unable to fetch URL %s status = %d", $url, $http_status);
        return NULL;
    } else {
        log_debug("get_url:\n%s", $responseText);
        return $responseText;
    }
}

/**
 * Clean up the SESSION variables.
 * @param String $persist  Whether to persist the login session
 * @return Int 1 if success. 0 if error.
 */
function clean_session($persist = 0)
{
    unset($_SESSION['get']);
    unset($_SESSION['rpfA']);
    if (!$persist) {
        unset($_SESSION['login']);
        unset($_SESSION['username']);
        unset($_SESSION['persist']);
        unset($_SESSION['ops']);
    }
    return true;
}

function send_error($url, $error, $description = NULL, $error_uri = NULL, $state = NULL, $response_mode = 'query', $http_error_code = '400')
{
    log_error("url:%s error:%s desc:%s uri:%s state:%s code:%d", $url, $error, $description, $error_uri, $state, $http_error_code);
    if ($url) {
        $params = array('error' => $error);
        if ($state) $params['state'] = $state;
        if ($description) $params['error_description'] = $description;

        if ($response_mode == 'form_post') {
            header("Cache-Control: no-store");
            header("Pragma: no-cache");
            echo make_form_post_response($url, $params);
            exit;
        } else {
            if ($response_mode == 'fragment')
                $separator = '#';
            else
                $separator = '?';
            $url .= $separator . http_build_query($params);
            header("Location: $url");
            exit;
        }
    } else {
        $json = array();
        if ($error)
            $json['error'] = $error;
        if ($description)
            $json['error_description'] = $description;
        if ($error_uri)
            $json['error_uri'] = $error_uri;
        if ($state)
            $json['state'] = $state;

        $codes = array(
            '400' => 'Bad Request',
            '401' => 'Unauthorized',
            '403' => 'Forbidden',
            '404' => 'Not Found',
            '405' => 'Method Not Allowed'
        );

        header("HTTP/1.0 {$http_error_code} {$codes[$http_error_code]}");
        header('Content-Type: application/json');
        header("Cache-Control: no-store");
        header("Pragma: no-cache");
        echo json_encode($json);
        log_error("HTTP/1.0 %d %s\n%s", $http_error_code, $codes[$http_error_code], json_encode($json));
        exit;
    }
}

function send_bearer_error($http_error_code, $error, $description = NULL)
{

    $codes = array(
        '400' => 'Bad Request',
        '401' => 'Unauthorized',
        '403' => 'Forbidden',
        '404' => 'Not Found',
        '405' => 'Method Not Allowed'
    );

    log_error("HTTP/1.0 %d %s", $http_error_code, $codes[$http_error_code]);
    header('WWW-Authenticate: Bearer error="' . $error . '"' . ($description ? ', error_description="' . $description . '"' : ''));
    header("HTTP/1.0 {$http_error_code} {$codes[$http_error_code]}");
    //    header("Cache-Control: no-store");
    //    header("Pragma: no-cache");
    exit;
}

function is_valid_registered_redirect_uri($redirect_uris, $uri)
{
    $uris = explode('|', $redirect_uris);
    if (in_array($uri, $uris))
        return true;
    else
        return false;
}


/**
 * Decrypts and Verifies a JWT
 * @param $jwt
 * @param $client Array Client Info
 * @param $allowed_sig_algs Array array of allowed signature 'alg' values
 * @param $allowed_enc_algs Array array of allowed encryption 'alg' values
 * @param $allowed_enc_encs Array array of allowed encryption 'enc' values
 * @param $error  String error code error_decrypt or error_sig
 * @return mixed null/decoded payload
 */
function decrypt_verify_jwt($jwt, $client, $allowed_sig_algs, $allowed_enc_algs, $allowed_enc_encs, &$error)
{
    $response = NULL;
    $jwt_parts = jwt_to_array($jwt);
    global $config;
    if (isset($jwt_parts[0]['enc'])) { // encrypted
        $signed_jwt = jwt_decrypt($jwt, $config['OP']['enc_pkey'], true, $config['OP']['op_enc_pkey_passphrase'], $allowed_enc_algs, $allowed_enc_encs);
        if (!$signed_jwt) {
            log_error('Unable to decrypt object');
            $error = 'error_decrypt';
            return NULL;
        } else
            log_debug("decrypted object = %s", $signed_jwt);
    } else
        $signed_jwt = $jwt;
    if ($signed_jwt) {
        list($header, $payload, $sig) = jwt_to_array($signed_jwt);
        $verified = false;
        if (substr($header['alg'], 0, 2) == 'HS') {
            $verified = jwt_verify($signed_jwt, $client['client_secret'], $allowed_sig_algs);
        } elseif (substr($header['alg'], 0, 2) == 'RS') {
            $pubkeys = array();
            if ($client['jwks_uri'])
                $pubkeys['jku'] = $client['jwks_uri'];
            if ($client['jwks'])
                $pubkeys['jwk'] = $client['jwks'];
            $verified = jwt_verify($signed_jwt, $pubkeys, $allowed_sig_algs);
        } elseif ($header['alg'] == 'none')
            $verified = true;
        log_debug("Signature Verification = $verified");
        if ($verified)
            $response = $payload;
        else
            $error = 'error_sig';
    }
    return $response;
}

function handle_auth()
{
    global $config;
    $state = isset($_REQUEST['state']) ? $_REQUEST['state'] : NULL;
    $error_page = OP_INDEX_PAGE;
    $response_mode = 'query';

    try {
        if (!isset($_REQUEST['client_id']))
            throw new OidcException('invalid_request', 'no client');
        // check client id
        $client = db_get_client($_REQUEST['client_id']);
        if (!$client)
            throw new OidcException('unauthorized_client', 'Client ID not found');

        if (isset($_REQUEST['redirect_uri'])) {
            if (!is_valid_registered_redirect_uri($client['redirect_uris'], $_REQUEST['redirect_uri']))
                throw new OidcException('invalid_request', 'no matching redirect_uri');
        } else
            throw new OidcException('invalid_request', 'no redirect_uri in request');

        $error_page = $_REQUEST['redirect_uri'];
        $response_mode = get_response_mode($_REQUEST);

        if (!isset($_REQUEST['response_type']))
            throw new OidcException('invalid_request', 'no response_type');
        $response_types = explode(' ', $_REQUEST['response_type']);
        $known_response_types = array('code', 'token', 'id_token');
        if (count(array_diff($response_types, $known_response_types)))
            throw new OidcException('invalid_response_type', "Unknown response_type {$_REQUEST['response_type']}");

        if ($config['OP']['enable_pkce']) {
            if (in_array('code', $response_types)) {
                if (!isset($_REQUEST['code_challenge']))
                    throw new OidcException('invalid_request', 'code challenge required');
                if (isset($_REQUEST['code_challenge_method'])) {
                    if (!in_array($_REQUEST['code_challenge_method'], array('plain', 'S256')))
                        throw new OidcException('invalid_request', "unsupported code challenge method {$_REQUEST['code_challenge_method']}");
                }
            }
        }

        if (!isset($_REQUEST['scope']))
            throw new OidcException('invalid_request', 'no scope');
        $scopes = explode(' ', $_REQUEST['scope']);
        if (!in_array('openid', $scopes))
            throw new OidcException('invalid_scope', 'no openid scope');

        if (in_array('token', $response_types) || in_array('id_token', $response_types)) {
            if (!isset($_REQUEST['nonce']))
                throw new OidcException('invalid_request', 'no nonce');
        }

        $_SESSION['get'] = $_GET;
        $request_uri = isset($_REQUEST['request_uri']) ? $_REQUEST['request_uri'] : NULL;

        $requested_userid = NULL;
        $requested_userid_display = NULL;
        $request_object = NULL;
        if ($request_uri) {
            $request_object = get_url($request_uri);
            if (!$request_object)
                throw new OidcException('invalid_request', "Unable to fetch request file $request_uri");
        } elseif (isset($_REQUEST['request']))
            $request_object = $_REQUEST['request'];
        if (isset($_GET['claims'])) {
            $_GET['claims'] = json_decode($_GET['claims'], true);
            $_REQUEST['claims'] = $_GET['claims'];
        }
        if (isset($request_object)) {
            $cryptoError = '';
            $allowed_sig_algs = empty($client['request_object_signing_alg']) ? null : array($client['request_object_signing_alg']);
            $allowed_enc_algs = empty($client['request_object_encryption_alg']) ? null :  array($client['request_object_encryption_alg']);
            $allowed_enc_encs = empty($client['request_object_encryption_enc']) ? null : array($client['request_object_encryption_enc']);
            $payload = decrypt_verify_jwt($request_object, $client, $allowed_sig_algs, $allowed_enc_algs, $allowed_enc_encs, $cryptoError);
            if (!isset($payload)) {
                if ($cryptoError == 'error_decrypt')
                    throw new OidcException('invalid_request', 'Unable to decrypt request object');
                elseif ($cryptoError == 'error_sig')
                    throw new OidcException('invalid_request', 'Unable to verify request object signature');
            } else {

                if (isset($payload['claims']['id_token'])) {
                    if (array_key_exists('sub', $payload['claims']['id_token']) && isset($payload['claims']['id_token']['sub']['value'])) {
                        $requested_userid_display = $payload['claims']['id_token']['sub']['value'];
                        $requested_userid = unwrap_userid($payload['claims']['id_token']['sub']['value']);
                        if (!db_get_user($requested_userid))
                            throw new OidcException('invalid_request', 'Unrecognized userid in request');
                    }
                }

                $merged_req = array_merge($_GET, $payload);
                if (!array_key_exists('max_age', $merged_req) && $client['default_max_age'])
                    $merged_req['max_age'] = $client['default_max_age'];
                if ($merged_req['max_age'])
                    $merged_req['claims']['id_token']['auth_time'] =  array('essential' => true);
                if ((!$merged_req['claims']['id_token'] || !array_key_exists('auth_time', $merged_req['claims']['id_token'])) && $client['require_auth_time'])
                    $merged_req['claims']['id_token']['auth_time'] = array('essential' => true);
                if (!$merged_req['claims']['id_token'] || !array_key_exists('acr', $merged_req['claims']['id_token'])) {
                    if ($merged_req['acr_values'])
                        $merged_req['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode(' ', $merged_req['acr_values']));
                    elseif ($client['default_acr_values'])
                        $merged_req['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode('|', $client['default_acr_values']));
                }
                $_SESSION['rpfA'] = $merged_req;

                log_debug("rpfA = %s", print_r($_SESSION['rpfA'], true));
                foreach (array('client_id', 'response_type', 'scope', 'nonce', 'redirect_uri') as $key) {
                    if (!isset($payload[$key]))
                        log_error("missing %s in payload => %s", $key, print_r($payload, true));
                    //                      throw new OidcException('invalid_request', 'Request Object missing required parameters');
                }

                log_debug("payload => %s", print_r($payload, true));
                foreach ($payload as $key => $value) {
                    if (isset($_REQUEST[$key]) && (strcmp($_REQUEST[$key], $value))) {
                        log_debug("key : %s value:%s", $key, print_r($value, true));
                        throw new OidcException('invalid_request', "Request Object Param Values do not match request '{$key}' '{$_REQUEST[$key]}' != '{$value}'");
                    }
                }
            }
        } else {
            if (isset($_GET['id_token_hint'])) {
                $cryptoError = '';
                $allowed_sig_algs = empty($client['id_token_signed_response_alg']) ? null : array($client['id_token_signed_response_alg']);
                $payload = decrypt_verify_jwt($_REQUEST['id_token_hint'], $client, $allowed_sig_algs, null, null, $cryptoError);
                if (!isset($payload)) {
                    if ($cryptoError == 'error_decrypt')
                        throw new OidcException('invalid_request', 'Unable to decrypt request object');
                    elseif ($cryptoError == 'error_sig')
                        throw new OidcException('invalid_request', 'Unable to verify request object signature');
                } else {
                    $requested_userid_display = $payload['sub'];
                    $requested_userid = unwrap_userid($payload['sub']);
                    if (!db_get_user($requested_userid))
                        throw new OidcException('invalid_request', 'Unrecognized userid in ID Token');
                }
            } else if (isset($_GET['claims']['id_token']['sub']['value'])) {
                $requested_userid_display = $_GET['claims']['id_token']['sub']['value'];
                $requested_userid = unwrap_userid($_GET['claims']['id_token']['sub']['value']);
                if (!db_get_user($requested_userid))
                    throw new OidcException('invalid_request', "Unrecognized userid in ID Token");
            } else if (isset($_GET['login_hint'])) {
                $principal = $_GET['login_hint'];

                $at = strpos($principal, '@');
                if ($at !== false) {
                    if ($at != 0) {    // XRI
                        // process email address
                        list($principal, $domain) = explode('@', $principal);
                        $port_pos = strpos($domain, ':');
                        if ($port_pos !== false)
                            $domain = substr($domain, 0, $port_pos);
                        $domain_parts = explode('.', $domain);
                        $server_parts = explode('.', $config['OP']['op_server_name']);
                        // check to see domain matches
                        $domain_start = count($domain_parts) - 1;
                        $server_start = count($server_parts) - 1;
                        $domain_match = true;
                        for ($i = $domain_start, $j = $server_start; $i >= 0 && $j >= 0; $i--, $j--) {
                            if (strcasecmp($domain_parts[$i], $server_parts[$j]) != 0) {
                                $domain_match = false;
                            }
                        }
                        if ($domain_match) {
                            $requested_userid_display = $principal;
                            $requested_userid = unwrap_userid($requested_userid_display);
                            if (!db_get_user($requested_userid)) {
                                $requested_userid_display = NULL;
                                $requested_userid = NULL;
                            }
                        } else
                            throw new OidcException('invalid_request', 'Unrecognized email domain');
                    }
                } else { // name only

                    $requested_userid_display = $_GET['login_hint'];
                    $requested_userid = unwrap_userid($requested_userid_display);
                    if (!db_get_user($requested_userid)) {
                        $requested_userid_display = NULL;
                        $requested_userid = NULL;
                    }
                }
            }

            if (!array_key_exists('max_age', $_REQUEST) && $client['default_max_age'])
                $_REQUEST['max_age'] = $client['default_max_age'];
            if (isset($_REQUEST['max_age']))
                $_REQUEST['claims']['id_token']['auth_time'] =  array('essential' => true);
            if ($client['require_auth_time'] && (array_key_exists('claims', $_REQUEST) && array_key_exists('id_token', $_REQUEST['claims']) &&  !$_REQUEST['claims']['id_token']
                || !array_key_exists('auth_time', $_REQUEST['claims']['id_token'])))
                $_REQUEST['claims']['id_token']['auth_time'] = array('essential' => true);
            if (!isset($_REQUEST['claims']) || !$_REQUEST['claims']['id_token'] || !array_key_exists('acr', $_REQUEST['claims']['id_token'])) {
                if (array_key_exists('acr_values', $_REQUEST))
                    $_REQUEST['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode(' ', $_REQUEST['acr_values']));
                elseif ($client['default_acr_values'])
                    $_REQUEST['claims']['id_token']['acr'] = array('essential' => true, 'values' => explode('|', $client['default_acr_values']));
            }

            $_SESSION['rpfA'] = $_REQUEST;
        }
        $prompt = array_key_exists('prompt', $_SESSION['rpfA']) && $_SESSION['rpfA']['prompt'] ? explode(' ', $_SESSION['rpfA']['prompt']) : array();
        $num_prompts = count($prompt);
        log_debug("num prompt = %d %s", $num_prompts,  print_r($prompt, true));
        if ($num_prompts > 1 && in_array('none', $prompt))
            throw new OidcException('interaction_required', "conflicting prompt parameters {$_SESSION['rpfA']['prompt']}");

        if (in_array('none', $prompt))
            $showUI = false;
        else
            $showUI = true;

        $_SESSION['client'] = $client;

        if (isset($_SESSION['username'])) {
            if (in_array('login', $prompt)) {
                echo loginform($requested_userid_display, $requested_userid, $client);
                exit();
            }
            if (isset($_SESSION['rpfA']['max_age'])) {
                if ((time() - $_SESSION['auth_time']) > $_SESSION['rpfA']['max_age']) {
                    if (!$showUI)
                        throw new OidcException('interaction_required', 'max_age exceeded and prompt set to none');
                    echo loginform($requested_userid_display, $requested_userid, $client);
                    exit;
                }
            }
            if ($requested_userid) {
                if ($_SESSION['username'] != $requested_userid) {
                    if (!$showUI)
                        throw new OidcException('interaction_required', 'requested account is different from logged in account, no UI requested');
                    else {
                        echo loginform($requested_userid_display, $requested_userid, $client);
                        exit;
                    }
                }
            }

            if (in_array('consent', $prompt)) {
                echo confirm_userinfo();
                exit();
            }
            if (!db_get_user_trusted_client($_SESSION['username'], $_REQUEST['client_id'])) {
                if (!$showUI)
                    throw new OidcException('interaction_required', 'consent needed and prompt set to none');
                echo confirm_userinfo();
            } else
                send_response($_SESSION['username'], true);
        } else {
            if (!$showUI)
                throw new OidcException('interaction_required', 'unauthenticated and prompt set to none');
            log_debug("SESSION : %s", print_r($_SESSION, true));
            echo loginform($requested_userid_display, $requested_userid, $client);
        }
    } catch (OidcException $e) {
        log_debug("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, $e->error_code, $e->desc, NULL, $state, $response_mode);
    } catch (Exception $e) {
        log_debug("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, 'invalid_request', $e->getMessage(), NULL, $state, $response_mode);
    }
}


function is_client_authenticated()
{

    try {
        global $config;
        $configop = $config['OP'];
        $auth_type = '';
        if (isset($_REQUEST['client_assertion_type'])) {
            $auth_type = $_REQUEST['client_assertion_type'];
            log_debug("client_assertion_type auth %s", $auth_type);
            if ($auth_type != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
                throw new OidcException('unauthorized_client', 'Unknown client_assertion_type');
            $jwt_assertion = $_REQUEST['client_assertion'];
            if (!isset($jwt_assertion))
                throw new OidcException('unauthorized_client', 'client_assertion not available');
            list($jwt_header, $jwt_payload, $jwt_sig) = jwt_to_array($jwt_assertion);
            if ($jwt_payload['iss'] != $jwt_payload['sub'])
                throw new OidcException('invalid request', 'JWT iss and prn mismatch');
            $client_id = $jwt_payload['iss'];
            log_debug("header = %s\npayload = %s\n", print_r($jwt_header, true), print_r($jwt_payload, true));
            log_debug("assertion = %s", $jwt_assertion);
            $alg_prefix = substr($jwt_header['alg'], 0, 2);
            if ($alg_prefix == "HS")
                $auth_type = 'client_secret_jwt';
            elseif ($alg_prefix == "RS")
                $auth_type = 'private_key_jwt';
            log_debug("auth_type = %s", $auth_type);
        } elseif (isset($_SERVER['PHP_AUTH_USER'])) {
            $client_id = $_SERVER['PHP_AUTH_USER'];
            if (isset($_SERVER['PHP_AUTH_PW']))
                $client_secret = $_SERVER['PHP_AUTH_PW'];
            $auth_type = 'client_secret_basic';
        } elseif (isset($_REQUEST['client_id'])) {
            $client_id = $_REQUEST['client_id'];
            if (isset($_REQUEST['client_secret']))
                $client_secret = $_REQUEST['client_secret'];
            $auth_type = 'client_secret_post';
        } else
            throw new OidcException('invalid_request', 'Unknown authentication type');

        if (!$client_id || !($client_secret || $jwt_assertion))
            throw new OidcException('invalid_client', 'no client or secret');

        // perform client_id and client_secret check
        $db_client = db_get_client($client_id);
        if ($db_client) {
            log_debug("%s\n%s", $db_client['client_id'], $db_client['token_endpoint_auth_method']);
            $db_client = $db_client->toArray();
            $token_endpoint_auth_method = $db_client['token_endpoint_auth_method'];
            if (!$token_endpoint_auth_method)
                $token_endpoint_auth_method = 'client_secret_basic';
        } else throw new OidcException('unauthorized_client', 'client_id not found');

        if ($token_endpoint_auth_method != $auth_type)
            throw new OidcException('unauthorized_client', "mismatched token endpoint auth type {$auth_type} != {$db_client['token_endpoint_auth_method']}");

        switch ($token_endpoint_auth_method) {
            case 'client_secret_basic':
            case 'client_secret_post':
                $client_authenticated = db_check_client_credential($client_id, $client_secret);
                log_info("authenticating client_id %s with client_secret %s\nResult : %d", $client_id, $client_secret, $client_authenticated);
                break;

            case 'client_secret_jwt':
                $allowed_sig_algs = empty($db_client['token_endpoint_auth_signing_alg']) ? null : ($db_client['token_endpoint_auth_signing_alg'] == 'none' ? array() : array($db_client['token_endpoint_auth_signing_alg']));
                $sig_verified = jwt_verify($jwt_assertion, $db_client['client_secret'], $allowed_sig_algs);
                if ($db_client['token_endpoint_auth_signing_alg'])
                    $alg_verified = $db_client['token_endpoint_auth_signing_alg'] == $jwt_header['alg'];
                else
                    $alg_verified = true;
                if (substr($_SERVER['PATH_INFO'], 0, 2) == '/1')
                    $audience = OP_INDEX_PAGE . '/1/token';
                else
                    $audience = OP_INDEX_PAGE . '/token';
                $key_aud = is_array($jwt_payload['aud']) ? $jwt_payload['aud'][0] : $jwt_payload['aud'];
                $aud_verified = in_array($key_aud, array($audience, $configop['op_url']));
                $now = time();
                $time_verified = abs(($now - $jwt_payload['iat']) <= 180) && abs(($now - $jwt_payload['exp']) < 180);
                if (!$sig_verified)
                    log_info("Sig not verified");
                if (!$aud_verified)
                    log_info("Aud not verified %s != %s", $jwt_payload['aud'], $audience);
                if (!$time_verified)
                    log_info('Time not verified');
                if (!$alg_verified)
                    log_info("Signing Alg does not match %s != %s", $jwt_header['alg'], $db_client['token_endpoint_auth_signing_alg']);
                $client_authenticated = $sig_verified && $aud_verified && $time_verified && $alg_verified;
                log_info(" client_secret_jwt Result : %d %d %d %d %d", $client_authenticated, $sig_verified, $aud_verified, $time_verified, $alg_verified);
                break;

            case 'private_key_jwt':
                $allowed_sig_algs = empty($db_client['token_endpoint_auth_signing_alg']) ? null : ($db_client['token_endpoint_auth_signing_alg'] == 'none' ? array() : array($db_client['token_endpoint_auth_signing_alg']));
                $pubkeys = array();
                if ($db_client['jwks_uri'])
                    $pubkeys['jku'] = $db_client['jwks_uri'];
                if ($db_client['jwks'])
                    $pubkeys['jwk'] = $db_client['jwks'];
                $sig_verified = jwt_verify($jwt_assertion, $pubkeys, $allowed_sig_algs);
                if ($db_client['token_endpoint_auth_signing_alg'])
                    $alg_verified = $db_client['token_endpoint_auth_signing_alg'] == $jwt_header['alg'];
                else
                    $alg_verified = true;
                if (substr($_SERVER['PATH_INFO'], 0, 2) == '/1')
                    $audience = OP_INDEX_PAGE . '/1/token';
                else
                    $audience = OP_INDEX_PAGE . '/token';
                $key_aud = is_array($jwt_payload['aud']) ? $jwt_payload['aud'][0] : $jwt_payload['aud'];
                $aud_verified = in_array($key_aud, array($audience, $configop['op_url']));
                $now = time();
                $time_verified = abs(($now - $jwt_payload['iat']) <= 180) && abs(($now - $jwt_payload['exp']) < 180);
                if (!$sig_verified)
                    log_info("Sig not verified");
                if (!$aud_verified)
                    log_info('Aud not verified');
                if (!$time_verified)
                    log_info('Time not verified');
                if (!$alg_verified)
                    log_info("Signing Alg does not match %s != %s", $jwt_header['alg'], $db_client['token_endpoint_auth_signing_alg']);
                $client_authenticated = $sig_verified && $aud_verified && $time_verified && $alg_verified;
                log_info("private_key_jwt Result : %d %d %d %d %d", $client_authenticated, $sig_verified, $aud_verified, $time_verified, $alg_verified);
                break;

            default:
                throw new OidcException('invalid_request', 'Unknown authentication type');
        }
        return $client_authenticated;
    } catch (OidcException $e) {
        send_error(NULL, $e->error_code, $e->desc);
    } catch (Exception $e) {
        send_error(NULL, '', $e->getMessage() . ' ' . $e->getTraceAsString());
    }
    return false;
}

function handle_token()
{
    global $config;
    log_info('****** handle_token');
    try {
        $grant_type = strtolower($_REQUEST['grant_type']);
        if (!$grant_type || $grant_type != 'authorization_code')
            throw new OidcException('unsupported_grant_type', "{$grant_type} is not supported");
        $code = $_REQUEST['code'];
        if (!$code)
            throw new OidcException('invalid_grant', 'No auth code');
        // check code
        $auth_code = db_find_auth_code($code);
        if (!$auth_code)
            throw new OidcException('invalid_grant', 'no such code');
        $request_info = json_decode($auth_code['info'], true);

        if (empty($_REQUEST['redirect_uri']))
            throw new OidcException('invalid_request', 'missing redirect_uri');
        log_info('%s <> %s', $_REQUEST['redirect_uri'], $request_info['g']['redirect_uri']);
        if ($_REQUEST['redirect_uri'] != $request_info['g']['redirect_uri']) {
            log_error('***  throwing redirect mismatch error');
            throw new OidcException('invalid_request', 'mismatch redirect_uri');
        }

        $client_authenticated = is_client_authenticated();
        if ($client_authenticated) {
            if ($config['OP']['enable_pkce']) {
                if (!isset($_REQUEST['code_verifier']))
                    throw new OidcException('invalid_grant', 'code verifier required');
                $code_verifier = $_REQUEST['code_verifier'];
                $code_challenge = $request_info['g']['code_challenge'];
                $code_challenge_method = $request_info['g']['code_challenge_method'] ? $request_info['g']['code_challenge_method'] : 'plain';

                $code_challenge_verified = false;
                if ($code_challenge_method == 'plain') {
                    if ($code_verifier == $code_challenge)
                        $code_challenge_verified = true;
                } else if ($code_challenge_method = 'S256') {
                    if (base64url_encode(hash('sha256', $code_verifier, true)) == $code_challenge) {
                        $code_challenge_verified = true;
                        log_debug("code challenge verified");
                    }
                }
                if (!$code_challenge_verified)
                    throw new OidcException('invalid_grant', 'code verifier mismatch');
            }

            while (true) {
                $token_name = base64url_encode(random_bytes(32));
                if (!db_find_token($token_name))
                    break;
            }
            $issue_at = new \DateTime();
            $expiration_at = new \Datetime('+30 hour');
            $fields = array(
                'client' => $auth_code['client'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $token_name,
                'details' => '',
                'token_type' => TOKEN_TYPE_ACCESS,
                'info' => $auth_code['info']
            );
            db_save_user_token($auth_code->getAccount()->getLogin(), $token_name, $fields);
            $access_token = $token_name;

            $response_types = explode(' ', $request_info['g']['response_type']);
            $scopes = explode(' ', $request_info['g']['scope']);
            $prompts = isset($request_info['g']['prompt']) ? explode(' ', $request_info['g']['prompt']) : [];
            if (in_array('openid', $scopes)) {
                $client_secret = null;
                $nonce = null;
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
                if (!$db_client)
                    throw new OidcException('invalid_request', 'invalid client');
                $sig = $db_client['id_token_signed_response_alg'];
                if (empty($sig))
                    $sig = 'RS256';
                $alg = $db_client['id_token_encrypted_response_alg'];
                $enc = $db_client['id_token_encrypted_response_enc'];

                log_debug("sig = '%s' alg='%s' enc='%s'", $sig, $alg, $enc);
                $client_secret = $db_client['client_secret'];
                $jwk_uri = $db_client['jwks_uri'];
                $jwks = $db_client['jwks'];


                if (isset($request_info['r']['session_id'])) {
                    session_id($request_info['r']['session_id']);
                    if (session_start()) {
                        if (isset($_SESSION['ops'])) {
                            $id_token_obj['ops'] = $request_info['r']['session_id'] . '.' . $_SESSION['ops'];
                        } else {
                            log_debug("no ops in sessionid %s", $request_info['r']['session_id']);
                        }
                    }
                }

                if ($request_info['g']['nonce'])
                    $nonce = $request_info['g']['nonce'];
                if ($sig) {
                    $bit_length = substr($sig, 2);
                    switch ($bit_length) {
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
                    if ($token_name)
                        $at_hash = base64url_encode(substr(hash($hash_alg, $token_name, true), 0, $hash_length));
                }

                if (isset($request_info['r']['claims']) && isset($request_info['r']['claims']['id_token'])) {
                    if (array_key_exists('auth_time', $request_info['r']['claims']['id_token'])) {
                        if (isset($request_info['r']['session_id'])) {
                            session_id($request_info['r']['session_id']);
                            if (session_start()) {
                                if (isset($_SESSION['auth_time'])) {
                                    $auth_time = (int) $_SESSION['auth_time'];
                                }
                            }
                        }
                        if (!isset($auth_time)) {
                            if (isset($request_info['r']['auth_time'])) {
                                $auth_time = (int) $request_info['r']['auth_time'];
                            }
                        }
                    }

                    if (array_key_exists('acr', $request_info['r']['claims']['id_token'])) {
                        if (array_key_exists('values', $request_info['r']['claims']['id_token']['acr'])) {
                            if (is_array($request_info['r']['claims']['id_token']['acr']['values']) && count($request_info['r']['claims']['id_token']['acr']['values']))
                                $acr = $request_info['r']['claims']['id_token']['acr']['values'][0];
                        } else
                            $acr = '0';
                    }
                }

                $requested_id_token_claims = get_id_token_claims($request_info['r']);
                log_debug('requested idtoken claims = %s', print_r($requested_id_token_claims, true));
                if ($requested_id_token_claims) {
                    $db_user = db_get_user($request_info['u']);
                    if (!$db_user)
                        throw new OidcException('invalid_request', 'no such user');
                    $idt_claims = get_account_claims($db_user, array_intersect_key($request_info['l'], $requested_id_token_claims));
                }
                $id_token_obj = make_id_token(wrap_userid($db_client, $request_info['u']), $config['OP']['op_url'], $db_client['client_id'], $idt_claims, $nonce, $c_hash, $at_hash, $auth_time, $ops, $acr);

                log_debug('handle_token id_token_obj = %s', print_r($id_token_obj, true));
                $cryptoError = '';
                $id_token = sign_encrypt($id_token_obj, $sig, $alg, $enc, $jwk_uri, $jwks, $client_secret, $cryptoError);

                if (!$id_token) {
                    log_error("ID Token cryptoError = %s", $cryptoError);
                    throw new OidcException('invalid request', "Idtoken crypto error {$cryptoError}");
                }
            }

            if (in_array('offline_access', $scopes) && in_array('code', $response_types) && in_array('token', $response_types) && in_array('consent', $prompts)) {
                while (true) {
                    $refresh_token_name = base64url_encode(random_bytes(32));
                    if (!db_find_token($refresh_token_name))
                        break;
                }
                $fields['token'] = $refresh_token_name;
                $fields['token_type'] = TOKEN_TYPE_REFRESH;
                $fields['expiration_at'] = strftime('%G-%m-%d %T', time() + (24 * 60 * 60));
                db_save_user_token($auth_code->getAccount()->getLogin(), $refresh_token_name, $fields);
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
            if (isset($refresh_token))
                $token_response['refresh_token'] = $refresh_token;
            if (isset($id_token))
                $token_response['id_token'] = $id_token;
            log_debug('token response = %s',  print_r($token_response, true));
            db_delete_entity($auth_code);
            echo json_encode($token_response);
        } else
            throw new OidcException('invalid_client', 'invalid client credentials');
    } catch (OidcException $e) {
        log_info('****** handle_token oidcexception');
        send_error(NULL, $e->error_code, $e->desc);
    } catch (BearerException $e) {
        log_info('****** handle_token BearerException');
        send_bearer_error('400', $e->error_code, $e->desc);
    } catch (Exception $e) {
        log_info('***** handle_token general exception');
    }
}

function handle_validatetoken()
{
    try {
        $access_token = $_REQUEST['access_token'];

        header("Content-Type: application/json");
        header("Cache-Control: no-store");
        header("Pragma: no-cache");

        # Make sure client authenticated w/ client_id and secret
        if (is_client_authenticated()) {
            $token = db_find_access_token($access_token);
            if ($token) {
                $db_client = db_get_client($token['client']);
                if (!$db_client)
                    throw new BearerException('invalid_request', 'Invalid Client ID');
                $tinfo = json_decode($token['info'], true);
                $userinfo = array();

                $db_user = db_get_user($tinfo['u']);

                if ($db_user && $db_user['enabled']) {
                    $scopes = explode(' ', $tinfo['g']['scope']);
                    if (in_array('openid', $scopes)) {
                        $userinfo['sub'] = wrap_userid($db_client, $tinfo['u']);
                    }
                    log_debug("userid = %s  unwrapped = %s", $userinfo['sub'], unwrap_userid($userinfo['sub']));
                    # throw new BearerException('invalid_request', 'Cannot find Access Token');

                    $token_response = array(
                        'active' =>  true,
                        'sub' => $userinfo['sub']
                    );
                } else {
                    $token_response = array(
                        'active' => false
                    );
                }
            } else {
                throw new BearerException('invalid_request', 'Cannot find Access Token');
            }
        } else {
            throw new OidcException('invalid_client', 'invalid client credentials');
        }
        header("Content-Type: application/json");
        header("Cache-Control: no-store");
        header("Pragma: no-cache");
        echo json_encode($token_response);
    } catch (OidcException $e) {
        send_error(NULL, $e->error_code, $e->desc);
    } catch (BearerException $e) {
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

function get_requested_claims($request, $subkeys)
{
    $requested_claims = array();
    foreach ($subkeys as $subkey) {
        if (isset($request['claims']) && is_array($request['claims']) && $request['claims'][$subkey] &&  is_array($request['claims'][$subkey]) && count($request['claims'][$subkey])) {
            foreach ($request['claims'][$subkey] as $key => $value) {
                $pound = strpos($key, '#');
                $key_name = $key;
                if ($pound !== false) {
                    $temp = substr($key, 0, $pound);
                    $locale = substr($key, $pound + 1);
                    if ($locale == 'ja-Kana-JP')
                        $key_name = $temp . '_ja_kana_jp';
                    elseif ($locale == 'ja_Hani-JP')
                        $key_name = $temp . '_ja_hani_jp';
                }
                if (in_array($key_name, array('auth_time', 'acr', 'sub')))
                    continue;
                $required = 0;
                if (is_array($value) && $value['essential'])
                    $required = 1;
                $requested_claims[$key_name] = max($requested_claims[$key_name], $required);
            }
        } else {
            log_debug("get_requested_claims [%s] = %d count = %d claims = %s", $subkey, isset($request['claims'][$subkey]), count($request['claims'][$subkey]), print_r($request['claims'][$subkey], true));
        }
    }
    return $requested_claims;
}

function get_userinfo_claims($request, $scopes)
{
    $requested_claims = array();
    $profile_claims = array();
    log_debug("get_userinfo_claims %s scopes = %s", print_r($request, true), print_r($scopes, true));
    if (isset($request['claims']) && isset($request['claims']['userinfo']))
        $requested_claims = get_requested_claims($request, array('userinfo'));
    if (is_string($scopes))
        $scopes = explode(' ', $scopes);
    if (!is_array($scopes)) {
        return array();
    }
    if (in_array('email', $scopes)) {
        $requested_claims['email'] = 0;
        $requested_claims['email_verified'] = 0;
    }
    if (in_array('address', $scopes))
        $requested_claims['address'] = 0;
    if (in_array('phone', $scopes)) {
        $requested_claims['phone_number'] = 0;
        $requested_claims['phone_number_verified'] = 0;
    }
    if (in_array('profile', $scopes)) {
        $profile_claims = get_default_claims();
        unset($profile_claims['email']);
        unset($profile_claims['email_verified']);
        unset($profile_claims['address']);
        unset($profile_claims['phone_number']);
        unset($profile_claims['phone_number_verified']);
        if (!isset($request['userinfo']['preferred_locales']))
            $request['userinfo']['preferred_locales'] = array();
        if (!in_array('ja-Kana-JP', $request['userinfo']['preferred_locales'])) {
            unset($profile_claims['name_ja_kana_jp']);
            unset($profile_claims['given_name_ja_kana_jp']);
            unset($profile_claims['family_name_ja_kana_jp']);
            unset($profile_claims['middle_name_ja_kana_jp']);
        }
        if (!in_array('ja-Hani-JP', $request['userinfo']['preferred_locales'])) {
            unset($profile_claims['name_ja_hani_jp']);
            unset($profile_claims['given_name_ja_hani_jp']);
            unset($profile_claims['family_name_ja_hani_jp']);
            unset($profile_claims['middle_name_ja_hani_jp']);
        }
        $profile_keys = array_keys($profile_claims);
        $num = count($profile_keys);
        if ($num)
            $profile_claims = array_combine($profile_keys, array_fill(0, $num, 0));
    }
    return array_merge($requested_claims, $profile_claims);
}

function get_id_token_claims($request)
{
    $requested_claims = array();
    $profile_claims = array();
    if (isset($request['claims']) && isset($request['claims']['id_token']))
        $requested_claims = get_requested_claims($request, array('id_token'));
    if ($request['response_type'] == 'id_token') {
        $scopes = $request['scope'];
        if (is_string($scopes))
            $scopes = explode(' ', $scopes);
        if (!is_array($scopes)) {
            return array();
        }
        if (in_array('email', $scopes)) {
            $requested_claims['email'] = 0;
            $requested_claims['email_verified'] = 0;
        }
        if (in_array('address', $scopes))
            $requested_claims['address'] = 0;
        if (in_array('phone', $scopes)) {
            $requested_claims['phone_number'] = 0;
            $requested_claims['phone_number_verified'] = 0;
        }
        if (in_array('profile', $scopes)) {
            $profile_claims = get_default_claims();
            unset($profile_claims['email']);
            unset($profile_claims['email_verified']);
            unset($profile_claims['address']);
            unset($profile_claims['phone_number']);
            unset($profile_claims['phone_number_verified']);
            $profile_keys = array_keys($profile_claims);
            $num = count($profile_keys);
            if ($num)
                $profile_claims = array_combine($profile_keys, array_fill(0, $num, 0));
        }
    }
    return array_merge($requested_claims, $profile_claims);
}

function get_all_requested_claims($request, $scope)
{
    $userinfo_claims = get_userinfo_claims($request, $scope);
    log_debug("userinfo claims = %s", print_r($userinfo_claims, true));
    $id_token_claims = get_id_token_claims($request);
    log_debug("id_token claims = %s", print_r($id_token_claims, true));
    $userinfo_keys = array_keys($userinfo_claims);
    $id_token_keys = array_keys($id_token_claims);
    $all_keys = array_unique(array_merge($userinfo_keys, $id_token_keys));
    sort($all_keys, SORT_STRING);
    log_debug("unique keys = %s", print_r($all_keys, true));
    $requested_claims = array();
    foreach ($all_keys as $key) {
        $userinfo_claim = 0;
        if (array_key_exists($key, $userinfo_claims)) {
            $userinfo_claim = $userinfo_claims[$key];
        }
        $id_token_claim = 0;
        if (array_key_exists($key, $id_token_claims)) {
            $id_token_claim = $id_token_claims[$key];
        }
        $requested_claims[$key] = max($userinfo_claim, $id_token_claim);
    }
    log_debug("requested_claims = %s", print_r($requested_claims, true));
    return $requested_claims;
}

function handle_userinfo()
{
    try {
        $token = $_REQUEST['access_token'];
        if (!$token) {
            $token = get_bearer_token();
            if (!$token)
                throw new BearerException('invalid_request', 'No Access Token');
        }
        // check code
        $token = db_find_access_token($token);
        if (!$token)
            throw new BearerException('invalid_request', 'Cannot find Access Token');
        $db_client = db_get_client($token['client']);
        if (!$db_client)
            throw new BearerException('invalid_request', 'Invalid Client ID');
        $tinfo = json_decode($token['info'], true);
        $userinfo = array();

        $db_user = db_get_user($tinfo['u']);
        $scopes = explode(' ', $tinfo['g']['scope']);
        if (in_array('openid', $scopes)) {
            $userinfo['sub'] = wrap_userid($db_client, $tinfo['u']);
        }
        log_debug("userid = %s  unwrapped = %s", $userinfo['sub'], unwrap_userid($userinfo['sub']));
        $requested_userinfo_claims = get_userinfo_claims($tinfo['r'], $tinfo['r']['scope']);

        log_debug("ALLOWED CLAIMS = %s", print_r($tinfo['l'], true));
        log_debug("REQUESTED_USER_INFO = %s", print_r($requested_userinfo_claims, true));

        $sig = $db_client['userinfo_signed_response_alg'];
        $alg = $db_client['userinfo_encrypted_response_alg'];
        $enc = $db_client['userinfo_encrypted_response_enc'];
        $client_secret = $db_client['client_secret'];
        $jwk_uri = $db_client['jwks_uri'];
        $jwks = $db_client['jwks'];

        $userinfo_claims = get_account_claims($db_user, array_intersect_key($tinfo['l'], $requested_userinfo_claims));
        $userinfo = array_merge($userinfo, $userinfo_claims);
        $sig_param = array('alg' => 'none');
        $sig_key = NULL;

        if ($sig || ($alg && $enc)) {
            $cryptoError = '';
            $userinfo_jwt = sign_encrypt($userinfo, $sig, $alg, $enc, $jwk_uri, $jwks, $client_secret, $cryptoError);
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
    } catch (BearerException $e) {
        send_bearer_error('401', $e->error_code, $e->desc);
    } catch (OidcException $e) {
        send_error('', $e->error_code, $e->desc);
    }
}

function get_bearer_token()
{
    $headers = array();
    $tmp_headers = apache_request_headers();
    foreach ($tmp_headers as $header => $value) {
        log_debug("$header: %s", $value);
        $headers[strtolower($header)] = $value;
    }
    $authorization = $headers['authorization'];
    log_debug('headers = %s', print_r($headers, true));
    log_debug("authorization header = %s", $authorization);
    if ($authorization) {
        $pieces = explode(' ', $authorization);
        log_debug('pieces = %s', print_r($pieces, true));
        if (strcasecmp($pieces[0], 'bearer') != 0) {
            log_error('No Bearer Access Token in Authorization Header');
            return null;
        }
        $token = rtrim($pieces[1]);
        log_debug("token = $token");
        return $token;
    }
    return null;
}

function handle_distributedinfo()
{

    try {
        global $signing_alg_values_supported, $encryption_alg_values_supported, $encryption_enc_values_supported, $config;

        $token = $_REQUEST['access_token'];
        if (!$token) {
            $token = get_bearer_token();
            if (!$token)
                throw new BearerException('invalid_request', 'No Access Token');
        }
        // check code
        $token = db_find_access_token($token);
        if (!$token)
            throw new BearerException('invalid_request', 'Cannot find Access Token');
        $db_client = db_get_client($token['client']);
        if (!$db_client)
            throw new BearerException('invalid_request', 'Invalid Client ID');
        $tinfo = json_decode($token['info'], true);
        $userinfo = array();
        $persona = db_get_user_persona($tinfo['u'], $tinfo['p'])->toArray();
        $scopes = explode(' ', $tinfo['g']['scope']);
        if (in_array('openid', $scopes)) {
            $userinfo['sub'] = wrap_userid($db_client, $tinfo['u']);
        }
        log_debug("userid = %s unwrapped = %s", $userinfo['sub'], unwrap_userid($userinfo['sub']));
        $requested_userinfo_claims = get_userinfo_claims($tinfo['r'], $tinfo['r']['scope']);
        $persona_custom_claims = db_get_user_persona_custom_claims($tinfo['u'], $tinfo['p']);
        foreach ($persona_custom_claims as $pcc) {
            $persona_claims[$pcc['claim']] = $pcc->PersonaCustomClaim[0]['value'];
        }

        log_debug("ALLOWED CLAIMS = %s", print_r($tinfo['l'], true));
        log_debug("REQUESTED_USER_INFO = %s", print_r($requested_userinfo_claims, true));
        $src = 0;
        foreach ($tinfo['l'] as $key) {
            if (array_key_exists($key, $requested_userinfo_claims)) {
                $prefix = substr($key, 0, 3);
                if ($prefix == 'ax.') {
                    $key = substr($key, 3);
                    $mapped_key = $key;
                    $kana = strpos($key, '_ja_kana_jp');
                    $hani = strpos($key, '_ja_hani_jp');
                    if ($kana !== false)
                        $mapped_key = substr($key, 0, $kana) . '#ja-Kana-JP';
                    if ($hani !== false)
                        $mapped_key = substr($key, 0, $hani) . '#ja-Hani-JP';
                    switch ($mapped_key) {
                        case 'address':
                            $userinfo[$mapped_key] = array(
                                'formatted' => $persona[$key]
                            );
                            break;

                        case 'email_verified':
                        case 'phone_number_verified':
                            if ($persona[$key])
                                $userinfo[$mapped_key] = true;
                            else
                                $userinfo[$mapped_key] = false;
                            break;

                        default:
                            $userinfo[$mapped_key] = $persona[$key];
                            break;
                    }
                } elseif ($prefix == 'cx.') {
                    $key = substr($key, 3);
                    $userinfo[$key] = $persona_claims[$key];
                }
            }
        }

        $sig_param = array('alg' => 'none');
        $sig_key = NULL;
        if ($db_client['userinfo_signed_response_alg']) {
            if (in_array($db_client['userinfo_signed_response_alg'], $signing_alg_values_supported)) {
                $sig_param['alg'] = $db_client['userinfo_signed_response_alg'];
                if (substr($db_client['userinfo_signed_response_alg'], 0, 2) == 'HS') {
                    $sig_key = $db_client['client_secret'];
                } elseif (substr($db_client['userinfo_signed_response_alg'], 0, 2) == 'RS') {
                    $configop = $config['OP'];
                    $sig_param['jku'] = $configop['jwk_url'];
                    $sig_param['kid'] = $configop['sig_kid'];
                    $sig_key = array('key_file' => $configop['sig_pkey'], 'password' => $configop['sig_pkey_passphrase']);
                }
                log_debug("DistributedInfo Using Sig Alg %s", $sig_param['alg']);
                $userinfo_jwt = jwt_sign($userinfo, $sig_param, $sig_key);
                if (!$userinfo_jwt) {
                    log_error("Unable to sign response for DistributedInfo");
                    send_bearer_error('400', 'invalid_request', 'Unable to sign response for DistributedInfo');
                }

                if ($db_client['userinfo_encrypted_response_alg'] && $db_client['userinfo_encrypted_response_enc']) {
                    log_debug("UserInfo Encryption Algs %s %s", $db_client['userinfo_encrypted_response_alg'], $db_client['userinfo_encrypted_response_enc']);
                    list($alg, $enc) = array($db_client['userinfo_encrypted_response_alg'], $db_client['userinfo_encrypted_response_enc']);
                    if (in_array($alg, $encryption_alg_values_supported) && in_array($enc, $encryption_enc_values_supported)) {
                        $jwk_uri = '';
                        $encryption_keys = NULL;
                        if ($db_client['jwks_uri']) {
                            $jwk = get_url($db_client['jwks_uri']);
                            if ($jwk) {
                                $jwk_uri = $db_client['jwks_uri'];
                                $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                                if (!$encryption_keys || !count($encryption_keys)) {
                                    $jwk_uri = NULL;
                                    if (!empty($db_client['jwks'])) {
                                        $encryption_keys = jwk_get_keys($db_client['jwks'], 'RSA', 'enc', NULL);
                                    }
                                    if (!$encryption_keys || !count($encryption_keys))
                                        $encryption_keys = NULL;
                                }
                            }
                        }
                        if (!$encryption_keys)
                            send_bearer_error('400', 'invalid_request', 'Unable to retrieve JWK key for encryption');
                        if ($jwk_uri)
                            $header_params = array('jku' => $jwk_uri);
                        if (isset($encryption_keys[0]['kid']))
                            $header_params['kid'] = $encryption_keys[0]['kid'];
                        $userinfo_jwt = jwt_encrypt2($userinfo_jwt, $encryption_keys[0], false, NULL, $header_params, NULL, $alg, $enc, false);
                        if (!$userinfo_jwt) {
                            log_error("Unable to encrypt response for DistributedInfo");
                            send_bearer_error('400', 'invalid_request', 'Unable to encrypt response for DistributedInfo');
                        }
                    } else {
                        log_error("UserInfo Encryption Algs %s and %s not supported", $alg, $enc);
                        send_bearer_error('400', 'invalid_request', 'Client registered unsupported encryption algs for UserInfo');
                    }
                }

                header("Content-Type: application/jwt");
                header("Cache-Control: no-store");
                header("Pragma: no-cache");

                log_debug('DistributedInfo response = %s', $userinfo_jwt);
                echo $userinfo_jwt;
            } else {
                log_error("UserInfo Sig Alg %s not supported", $db_client['userinfo_signed_response_alg']);
                send_bearer_error('400', 'invalid_request', "UserInfo Sig Alg {$db_client['userinfo_signed_response_alg']} not supported");
            }
        } else {
            header("Cache-Control: no-store");
            header("Pragma: no-cache");
            header("Content-Type: application/json");
            log_debug('DistributedInfo response = %s', json_encode($userinfo));
            echo json_encode($userinfo);
        }
    } catch (BearerException $e) {
        send_bearer_error('401', $e->error_code, $e->desc);
    } catch (OidcException $e) {
        send_error('', $e->error_code, $e->desc);
    }
}

/**
 * Mark the user as authenticated and either return the consent form 
 * or send the authentication response
 * @param string $username Username of the authenticated user
 */
function after_authentication($username, $persist = false) {
    $_SESSION['login'] = 1;
    $_SESSION['username'] = $username;
    $_SESSION['persist'] = $persist;
    $_SESSION['auth_time'] = time();
    $_SESSION['ops'] = bin2hex(random_bytes(16));
    setcookie('ops', $_SESSION['ops'], 0, '/');
    log_debug("Auth_time = %s", $_SESSION['auth_time']);
    log_debug("session id = %s", session_id());
    log_debug("prompt = %s", @$_SESSION['rpfA']['prompt']);
    $prompt = isset($_SESSION['rpfA']['prompt']) ? explode(' ', $_SESSION['rpfA']['prompt']) : array();
    $num_prompts = count($prompt);
    if ($num_prompts > 1 && in_array('none', $prompt)) {
        throw new OidcException('interaction_required', "conflicting prompt parameters {$_SESSION['rpfA']['prompt']}");
    }
    if (in_array('none', $prompt))
        $showUI = false;
    else
        $showUI = true;
    if (in_array('consent', $prompt) || !db_get_user_trusted_client($username, $_SESSION['rpfA']['client_id'])) {
        if (!$showUI)
            throw new OidcException('interaction_required', "Unable to show consent page, prompt set to none");
        echo confirm_userinfo();
    } else
        send_response($username, true);
}

/**
 * Validate credentials for local authentication
 */
function handle_login()
{
    // $username=preg_replace('/[^\w=_@]/','_',$_POST['username']);
    $username = $_POST['username'];
    try {
        if ($username) {
            if (db_check_credential($username, $_POST['password'])) {
                after_authentication($username, $_POST['persist']);
            } else { // Credential did not match so try again.
                echo loginform(@$_REQUEST['display_name'], $username, $_SESSION['client'], false, true);
            }
        } else {
            echo loginform($_SESSION["user"]['display_name'], $_SESSION["user"]['username'], $_SESSION['client'], false, false);
        }
    } catch (OidcException $e) {
        send_error($_REQUEST['redirect_uri'], $e->error_code, $e->desc, NULL, $_REQUEST['state']);
    }
}

function handle_confirm_userinfo()
{
    $rpfA = @$_SESSION['rpfA'];
    $client_id = @$rpfA['client_id'];
    $authorized = false;
    if ($_REQUEST['confirm'] == 'confirmed') {
        $authorized = true;
    }
    $trusted_site = db_get_user_trusted_client($_SESSION['username'], $client_id);
    if ($_REQUEST['trust'] == 'always') {
        log_debug("Trust = Always for %s", $client_id);
        if (!$trusted_site)
            db_save_user_trusted_client($_SESSION['username'], $client_id);
    } else {
        if ($trusted_site)
            db_delete_user_trusted_client($_SESSION['username'], $client_id);
    }

    send_response($_SESSION['username'], $authorized);
}

function handle_file($file)
{
    echo file_get_contents($file);
}

function handle_default($file = null)
{

    if ($file && is_file(__DIR__ . $file)) {
        log_info("file = %s", __DIR__ . $file);
        echo file_get_contents(__DIR__ . $file);
        exit;
    }
    global $blade;
    $error = $_REQUEST['error'];
    $desc = $_REQUEST['error_description'];

    if (!isset($error)) {
        $error = '"' . $file . '" not found';
    }

    $str = $blade->run("error", [
        'error' => $error,
        'desc' => $desc,
    ]);
    echo $str;
}

function check_redirect_uris($uris)
{
    $valid = true;
    if ($uris) {
        foreach ($uris as $uri) {
            if (strpos($uri, '#') !== false) {
                $valid = false;
                break;
            }
        }
    } else
        $valid = false;
    return $valid;
}

function handle_client_registration()
{
    global $config;
    if (!$config['site']['enable_dynamic_client_registration']) {
        send_error(null,'invalid_request', 'Dynamic client registration disabled');
    }

    try {
        global $signing_alg_values_supported, $encryption_alg_values_supported, $encryption_enc_values_supported;
        $tmp_headers = apache_request_headers();
        foreach ($tmp_headers as $header => $value) {
            $headers[strtolower($header)] = $value;
        }
        if (!$headers['content-type'] || substr($headers['content-type'], 0, 16) != 'application/json') {
            throw new OidcException('invalid_client_metadata', 'Unexpected content type');
        }
        $json = file_get_contents('php://input');
        log_debug('Registration data %s', $json);
        if (!$json) {
            log_error('No JSON body in registration');
            throw new OidcException('invalid_client_metadata', 'No JSON body');
        }
        $data = json_decode($json, true);
        if (!$data) {
            log_error('Invalid JSON');
            throw new OidcException('invalid_client_metadata', 'Invalid JSON');
        }

        $keys = array(
            'contacts' => NULL,
            'application_type' => NULL,
            'client_name' => NULL,
            'logo_uri' => NULL,
            'redirect_uris' => NULL,
            'post_logout_redirect_uris' => NULL,
            'token_endpoint_auth_method' => array('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'client_secret_jwt'),
            'token_endpoint_auth_signing_alg' => $signing_alg_values_supported,
            'policy_uri' => NULL,
            'tos_uri' => NULL,
            'jwks_uri' => NULL,
            'jwks' => NULL,
            'sector_identifier_uri' => NULL,
            'subject_type' => array('pairwise', 'public'),
            'request_object_signing_alg' => $signing_alg_values_supported,
            'userinfo_signed_response_alg' => $signing_alg_values_supported,
            'userinfo_encrypted_response_alg' => $encryption_alg_values_supported,
            'userinfo_encrypted_response_enc' => $encryption_enc_values_supported,
            'id_token_signed_response_alg' => $signing_alg_values_supported,
            'id_token_encrypted_response_alg' => $encryption_alg_values_supported,
            'id_token_encrypted_response_enc' => $encryption_enc_values_supported,
            'default_max_age' => NULL,
            'require_auth_time' => NULL,
            'default_acr_values' => NULL,
            'initiate_login_uri' => NULL,
            'request_uris' => NULL,
            'response_types' => NULL,
            'grant_types' => NULL,

        );

        $client_id = base64url_encode(random_bytes(16));
        $client_secret = base64url_encode(random_bytes(10));
        $reg_token = base64url_encode(random_bytes(10));
        $reg_client_uri_path = base64url_encode(random_bytes(16));
        $params = array(
            'client_id' => $client_id,
            'client_id_issued_at' => time(),
            'client_secret' => $client_secret,
            'client_secret_expires_at' => 0,
            'registration_access_token' => $reg_token,
            'registration_client_uri_path' => $reg_client_uri_path
        );
        foreach ($keys as $key => $supported_values) {
            if (isset($data[$key])) {
                if (in_array($key, array('contacts', 'redirect_uris', 'request_uris', 'post_logout_redirect_uris', 'grant_types', 'response_types', 'default_acr_values')))
                    $params[$key] = implode('|', $data[$key]);
                else if ($key == 'jwks') {
                    $params[$key] = json_encode($data[$key]);
                } else
                    $params[$key] = $data[$key];
                if (!empty($supported_values)) {
                    if (!in_array($params[$key], $supported_values))
                        throw new OidcException('invalid_client_metadata', "Unsupported {$key} value : {$params[$key]}");
                }
            }
        }
        if (!check_redirect_uris($data['redirect_uris'])) {
            throw new OidcException('invalid_redirect_uri', 'redirect_uris is invalid');
        }
        if (isset($data['post_logout_redirect_uris']) && !check_redirect_uris($data['post_logout_redirect_uris'])) {
            throw new OidcException('invalid_client_metadata', 'post_logout_redirect_uris is invalid');
        }
        if (array_key_exists('sector_identifier_uri', $data)) {
            $sectorUris = get_url($data['sector_identifier_uri']);
            if (!$sectorUris)
                throw new OidcException('invalid_client_metadata', 'blank sector_identifier_uri contents');
            $sectorJson = json_decode($sectorUris, true);
            log_debug("sectorUris = %s redirectUris = %s", print_r($sectorJson, true), print_r($data['redirect_uris'], true));
            if (!is_array($sectorJson))
                throw new OidcException('invalid_client_metadata', 'invalid sector_identifier_uri contents');
            if (count($data['redirect_uris']) != count($sectorJson))
                throw new OidcException('invalid_client_metadata', 'sector_identifier_uri count mismatch');
            foreach ($sectorJson as $sectorId) {
                if (!in_array($sectorId, $data['redirect_uris']))
                    throw new OidcException('invalid_client_metadata', 'sector_identifier_uri contents mismatch');
            }
        }
        if (isset($params['require_auth_time'])) {
            if ($params['require_auth_time'])
                $params['require_auth_time'] = 1;
            else
                $params['require_auth_time'] = 0;
        }
        log_debug("client registration params = %s", print_r($params, true));
        db_save_client($client_id, $params);
        $reg_uri = OP_INDEX_PAGE . '/client/' . $reg_client_uri_path;
        unset($params['registration_client_uri_path']);

        $client_json = array(
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
        $array_params = array('contacts', 'redirect_uris', 'request_uris', 'post_logout_redirect_uris', 'response_types', 'grant_types', 'default_acr_values');
        foreach ($array_params as $aparam) {
            if (isset($params[$aparam]))
                $params[$aparam] = explode('|', $params[$aparam]);
        }
        if (!empty($params['jwks']))
            $params['jwks'] = json_decode($params['jwks'], true);
        if (isset($params['require_auth_time']))
            $params['require_auth_time'] = $params['require_auth_time'] == 1;
        echo json_encode(array_merge($client_json, $params));
    } catch (OidcException $e) {
        send_error(NULL, $e->error_code, $e->desc);
    } catch (Exception $e) {
        send_error(NULL, 'invalid_client_metadata', $e->desc . ' ' . $e->getTraceAsString());
    }
}

function handle_client_operations()
{
    global $config;
    if (!$config['site']['enable_dynamic_client_registration']) {
        send_error(null,'invalid_request', 'Dynamic client registration disabled');
    }
    try {
        $token = $_REQUEST['access_token'];
        if (!$token) {
            $token = get_bearer_token();
            if (!$token)
                throw new BearerException('invalid_request', 'No Access Code');
        }

        $pos = strpos($_SERVER['PATH_INFO'], '/client/');
        if ($pos === false)
            throw new OidcException('invailid_request', 'Invalid path');

        $uri_path = substr($_SERVER['PATH_INFO'], $pos + 8);
        $db_client = db_get_client_by_registration_uri_path($uri_path);
        if (!$db_client)
            throw new OidcException('invalid_request', 'Invalid client');
        if ($db_client['registration_access_token'] != $token)
            throw new OidcException('invalid _request', 'Invalid registration token');
        $params = $db_client->toArray();

        unset($params['id']);
        unset($params['registration_access_token']);
        unset($params['registration_client_uri_path']);
        unset($params['jwk_encryption_uri']);
        unset($params['x509_uri']);
        unset($params['x509_encryption_uri']);
        $array_params = array('contacts', 'redirect_uris', 'request_uris', 'post_logout_redirect_uris', 'response_types', 'grant_types', 'default_acr_values');
        foreach ($params as $key => $value) {
            if ($value) {
                if (in_array($key, $array_params))
                    $params[$key] = explode('|', $value);
            } else
                unset($params[$key]);
        }
        if (!empty($params['jwks']))
            $params['jwks'] = json_decode($params['jwks'], true);
        if ($params['require_auth_time'])
            $params['require_auth_time'] = $params['require_auth_time'] == 1;
        header("Cache-Control: no-store");
        header("Pragma: no-cache");
        header('Content-Type: application/json');
        echo pretty_json(json_encode($params));
    } catch (BearerException $e) {
        send_error(NULL, $e->error_code, $e->desc, NULL, true, '403');
    } catch (OidcException $e) {
        send_error(NULL, $e->error_code, $e->desc, NULL, true, '403');
    }
}

function wrap_userid($dbclient, $userid)
{
    if ($dbclient['subject_type'] == 'public')
        return $userid;
    else {  // generate pairwise
        $str = gzencode($dbclient['id'] . ':' . $userid, 9);
        $wrapped = bin2hex(aes_128_cbc_encrypt($str, '1234567890123456', '0101010101010101'));
        log_debug("user id %s wrapped = %s", $userid, $wrapped);
        return $wrapped;
    }
}

function unwrap_userid($userid)
{
    $account = db_get_user($userid);
    if ($account) {
        return $userid;
    } else {
        $str = pack("H*", $userid);

        $unwrapped_name = gzdecode(aes_128_cbc_decrypt($str, '1234567890123456', '0101010101010101'));
        log_debug("wrapped %s unwrapped = %s", $str, $unwrapped_name);
        $parts = explode(':', $unwrapped_name);
        return $parts[1];
    }
    return NULL;
}

function handle_end_session()
{
    $id_token = isset($_REQUEST['id_token']) ? $_REQUEST['id_token'] : '';
    $post_logout_url = isset($_REQUEST['post_logout_redirect_uri']) ? $_REQUEST['post_logout_redirect_uri'] : '';
    setcookie('ops', "", time() - 3600, '/');
    session_destroy();
    if ($post_logout_url)
        header('Location:' . $post_logout_url);
}

function handle_logout()
{
    clean_session();
    setcookie('ops', "", time() - 3600, '/');
    session_destroy();
}

function make_id_token($username, $issuer, $aud, $claims = array(), $nonce = NULL, $code_hash = NULL, $token_hash = NULL, $auth_time = NULL, $ops = NULL, $acr = NULL)
{
    $id_token_obj = array(
        'iss' => $issuer,
        'sub' => $username,
        'aud' => array($aud),
        'exp' => time() + 5 * (60),
        'iat' => time()
    );

    if (isset($nonce))
        $id_token_obj['nonce'] = $nonce;
    if (isset($code_hash))
        $id_token_obj['c_hash'] = $code_hash;
    if (isset($token_hash))
        $id_token_obj['at_hash'] = $token_hash;
    if (isset($ops))
        $id_token_obj['ops'] = $ops;
    if (isset($auth_time))
        $id_token_obj['auth_time'] = $auth_time;
    if (isset($acr))
        $id_token_obj['acr'] = $acr;
    foreach ($claims as $k => $v) {
        $id_token_obj[$k] = $v;
    }
    return $id_token_obj;
}

function get_account_claims($db_user, $requested_claims)
{
    $claims = array();
    global $config;
    log_debug("account requested claims = %s", print_r($requested_claims, true));
    foreach ($requested_claims as $key => $value) {
        $mapped_key = $key;
        $kana = strpos($key, '_ja_kana_jp');
        $hani = strpos($key, '_ja_hani_jp');
        if ($kana !== false)
            $mapped_key = substr($key, 0, $kana) . '#ja-Kana-JP';
        if ($hani !== false)
            $mapped_key = substr($key, 0, $hani) . '#ja-Hani-JP';
        switch ($mapped_key) {
            case 'address':
                $claims[$mapped_key] = array(
                    'formatted' => $db_user[$key]
                );
                break;

            case 'email_verified':
            case 'phone_number_verified':
                if (isset($db_user[$key]))
                    $claims[$mapped_key] = true;
                else
                    $claims[$mapped_key] = false;
                break;

            case 'updated_at':
                if (isset($db_user[$key])) {
                    $claims[$mapped_key] = $db_user[$key]->getTimestamp();
                }
                break;

            default:
                $claims[$mapped_key] = $db_user[$key];
                break;
        }
    }
    log_debug('returning = %s', print_r($claims, true));
    return $claims;
}

function get_response_mode($req)
{
    if (isset($req['response_mode'])) {
        if (in_array($req['response_mode'], array('fragment', 'query', 'form_post')))
            return $req['response_mode'];
    }
    if ($req['response_type'] == 'code' || empty($req['response_type']))
        return 'query';
    else
        return 'fragment';
}

function make_form_post_response($url, $params)
{

    $pairs = '';
    $type = 'hidden';
    foreach ($params as $key => $value) {
        $pairs .= "<input type='{$type}' name='{$key}' value='{$value}'>";
    }

    $html = <<<EOF
<html>
<head>
    <title >Form Test</title>
    <script type="text/javascript">
        function submitform() {
            document.forms[0].submit();
        }
    </script>
</head>
<body onload='submitform();'>
<form id='myform' name='myform' method='post' action='{$url}'>
$pairs
</form>
</body>
</html>
EOF;
    return $html;
}

function send_auth_response($url, $params, $response_mode)
{
    log_debug('URL = %s params = %s mode = %s', $url, print_r($params, true), $response_mode);
    if ($response_mode == 'form_post') {
        echo make_form_post_response($url, $params);
    } else {
        if ($response_mode == 'fragment')
            $separator = '#';
        else
            $separator = '?';
        $url .= $separator . http_build_query($params);
        log_debug("redirect to %s", $url);
        header("Location: $url");
    }
}

function send_response($username, $authorize = false)
{
    global $config;
    $GET = $_SESSION['get'];
    $rpfA = $_SESSION['rpfA'];
    $rpep = $GET['redirect_uri'];
    $state = isset($GET['state']) ? $GET['state'] : null;
    $error_page = isset($GET['redirect_uri']) ? $GET['redirect_uri'] : OP_INDEX_PAGE;
    $response_mode = get_response_mode($GET);

    try {
        $client_id = $GET['client_id'];
        $response_types = isset($GET['response_type']) ? explode(' ', $GET['response_type']) : [];
        $scopes = isset($GET['scope']) ? explode(' ', $GET['scope']) : [];
        $prompts = isset($GET['prompt']) ? explode(' ', $GET['prompt']) : [];

        $is_code_flow = in_array('code', $response_types);
        $is_token_flow = in_array('token', $response_types);
        $is_id_token = in_array('id_token', $response_types);

        $offline_access = $is_code_flow && !$is_token_flow && in_array('consent', $prompts) && in_array('offline_access', $scopes);

        $issue_at = new \DateTime();
        $expiration_at = new \DateTime('+2 hour');
        $response_params = array();

        if (!$authorize)
            throw new OidcException('access_denied', 'User denied access');

        $rpfA['session_id'] = session_id();
        $rpfA['auth_time'] = $_SESSION['auth_time'];
        $confirmed_attribute_list = get_all_requested_claims($rpfA, $GET['scope']);

        if ($is_code_flow) {
            $code_info = create_token_info($username, $confirmed_attribute_list, $GET, $rpfA);
            $code = $code_info['name'];
            unset($code_info['name']);
            $fields = array(
                'client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $code,
                'details' => '',
                'token_type' => TOKEN_TYPE_AUTH_CODE,
                'info' => json_encode($code_info)
            );
            db_save_user_token($username, $code, $fields);
        }
        if ($is_token_flow) {
            $code_info = create_token_info($username, $confirmed_attribute_list, $GET, $rpfA);
            $token = $code_info['name'];
            unset($code_info['name']);
            $fields = array(
                'client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $token,
                'details' => '',
                'token_type' => TOKEN_TYPE_ACCESS,
                'info' => json_encode($code_info)
            );
            db_save_user_token($username, $token, $fields);
        }

        if ($offline_access) {
            while (true) {
                $refresh_token_name = base64url_encode(random_bytes(32));
                if (!db_find_token($refresh_token_name))
                    break;
            }
            $fields = array(
                'client' => $GET['client_id'],
                'issued_at' => $issue_at,
                'expiration_at' => $expiration_at,
                'token' => $refresh_token_name,
                'details' => '',
                'token_type' => TOKEN_TYPE_REFRESH,
                'info' => json_encode($code_info)
            );
            $fields['expiration_at'] = strftime('%G-%m-%d %T', time() + (24 * 60 * 60));
            db_save_user_token($username, $refresh_token_name, $fields);
        }

        // Handle response_type for code or token
        if (isset($GET['state']))
            $response_params['state'] = $GET['state'];
        if ($is_token_flow || $is_id_token) {
            if (isset($token)) {
                $response_params['access_token'] = $token;
                $response_params['token_type'] = 'Bearer';
                if ($offline_access)
                    $response_params['refresh_token'] = $refresh_token_name;
                $response_params['expires_in'] = '3600';
            }
        }
        if ($is_id_token) {

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
            if ($db_client) {
                $sig = $db_client['id_token_signed_response_alg'];
                if (!isset($sig))
                    $sig = 'RS256';
                $alg = $db_client['id_token_encrypted_response_alg'];
                $enc = $db_client['id_token_encrypted_response_enc'];
                $client_secret = $db_client['client_secret'];
                $jwk_uri = $db_client['jwks_uri'];
                $jwks = $db_client['jwks'];
            }

            if (isset($rpfA['claims']) && isset($rpfA['claims']['id_token'])) {
                if (array_key_exists('auth_time', $rpfA['claims']['id_token']))
                    $auth_time = (int) $_SESSION['auth_time'];

                if (array_key_exists('acr', $rpfA['claims']['id_token'])) {
                    if (array_key_exists('values', $rpfA['claims']['id_token']['acr'])) {
                        if (is_array($rpfA['claims']['id_token']['acr']['values']) && count($rpfA['claims']['id_token']['acr']['values']))
                            $acr = $rpfA['claims']['id_token']['acr']['values'][0];
                    } else
                        $acr = '0';
                }
            }
            if ($sig) {
                $bit_length = substr($sig, 2);
                switch ($bit_length) {
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
                if ($code)
                    $c_hash = base64url_encode(substr(hash($hash_alg, $code, true), 0, $hash_length));
                if (isset($token))
                    $at_hash = base64url_encode(substr(hash($hash_alg, $token, true), 0, $hash_length));
            }
            $requested_id_token_claims = get_id_token_claims($rpfA);
            if ($requested_id_token_claims) {
                $db_user = db_get_user($username);
                if ($db_user)
                    $idt_claims = get_account_claims($db_user, $requested_id_token_claims);
                else
                    throw new OidcException('access_denied', 'no such user');
            }
            $id_token_obj = make_id_token(wrap_userid($db_client, $username), $config['OP']['op_url'], $client_id, $idt_claims, $nonce, $c_hash, $at_hash, $auth_time, $ops, $acr);

            log_debug('sen_response id_token_obj = %s', print_r($id_token_obj, true));
            $cryptoError = null;
            $id_token = sign_encrypt($id_token_obj, $sig, $alg, $enc, $jwk_uri, $jwks, $client_secret, $cryptoError);

            if (!$id_token) {
                log_error("Unable to sign encrypt response for ID Token %s", $cryptoError);
                throw new OidcException('invalid_request', "idtoken crypto error {$cryptoError}");
            }
            $response_params['id_token'] = $id_token;
        }
        $url_parts = parse_url($rpep);
        $origin = sprintf("%s://%s%s", $url_parts['scheme'], $url_parts['host'], isset($url_parts['port']) ? ':' . $url_parts['port'] : '');
        $salt = bin2hex(random_bytes(16));
        log_debug("ss = sha256(%s%s%s%s).%s", $client_id, $origin, $_SESSION['ops'], $salt, $salt);
        $session_state = hash('sha256', "{$client_id}{$origin}{$_SESSION['ops']}{$salt}") . '.' . $salt;
        $response_params['session_state'] = $session_state;

        if ($is_code_flow) {
            $response_params['code'] = $code;
        }

        if ($_SESSION['persist'] == 'on') {
            $username = $_SESSION['username'];
            $auth_time = $_SESSION['auth_time'];
            $ops = $_SESSION['ops'];
            $login = $_SESSION['login'];
            clean_session();
            $_SESSION['lastlogin'] = time();
            $_SESSION['username'] = $username;
            $_SESSION['auth_time'] = $auth_time;
            $_SESSION['ops'] = $ops;
            $_SESSION['login'] = $login;
            $_SESSION['persist'] = 'on';
        } else {
            session_destroy();
        }
        send_auth_response($rpep, $response_params, $response_mode);
    } catch (OidcException $e) {
        log_error("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, $e->error_code, $e->desc, NULL, $state, $response_mode);
    } catch (Exception $e) {
        log_error("handle_auth exception : %s", $e->getTraceAsString());
        send_error($error_page, 'invalid_request', $e->getMessage(), NULL, $state, $response_mode);
    }
}

function sign_encrypt($payload, $sig, $alg, $enc, $jwks_uri = null, $jwks = null, $client_secret = null, &$cryptoError = null)
{
    global $signing_alg_values_supported, $encryption_alg_values_supported, $encryption_enc_values_supported, $config;
    log_debug("sign_encrypt sig = %s alg = %s enc = %s", $sig, $alg, $enc);
    $jwt = is_array($payload) ? json_encode($payload) : $payload;

    if (isset($sig) && !empty($sig)) {
        $sig_param = array('alg' => 'none');
        $sig_key = NULL;
        if (in_array($sig, $signing_alg_values_supported)) {
            $sig_param['alg'] = $sig;
            if (substr($sig, 0, 2) == 'HS') {
                $sig_key = $client_secret;
            } elseif (substr($sig, 0, 2) == 'RS') {
                $configop = $config['OP'];
                $sig_param['jku'] = $configop['jwk_url'];
                $sig_param['kid'] = $configop['sig_kid'];
                $sig_key = array('key_file' => $configop['sig_pkey'], 'password' => $configop['sig_pkey_passphrase']);
            }
        } else {
            log_error("sig alg %s not supported", $sig);
            if ($cryptoError)
                $cryptoError = 'error_sig';
            return null;
        }
        $jwt = jwt_sign($jwt, $sig_param, $sig_key);
        if (!$jwt) {
            if ($cryptoError)
                $cryptoError = 'error_sig';
            log_error("Unable to sign payload %s", $jwt);
            return null;
        }

        log_debug('jws = %s', $jwt);
    }

    if (isset($alg) && isset($enc) && !empty($alg) && !empty($enc)) {
        if (in_array($alg, $encryption_alg_values_supported) && in_array($enc, $encryption_enc_values_supported)) {
            $jwk_uri = '';
            $encryption_keys = NULL;
            if ($jwks_uri) {
                $jwk = get_url($jwks_uri);
                if ($jwk) {
                    $jwk_uri = $jwks_uri;
                    $encryption_keys = jwk_get_keys($jwk, 'RSA', 'enc', NULL);
                    if (!$encryption_keys || !count($encryption_keys))
                        $encryption_keys = NULL;
                }
            }
            if (!$encryption_keys && !empty($jwks)) {
                $encryption_keys = jwk_get_keys($jwks, 'RSA', 'enc', NULL);
                if (!$encryption_keys || !count($encryption_keys))
                    $encryption_keys = NULL;
                $jwk_uri = NULL;
            }
            if (!$encryption_keys) {
                if ($cryptoError)
                    $cryptoError = 'error_enc';
                log_error("Unable to get enc keys");
                return null;
            }
            if (!empty($jwk_uri))
                $header_params = array('jku' => $jwk_uri);
            if (isset($encryption_keys[0]['kid']))
                $header_params['kid'] = $encryption_keys[0]['kid'];
            $jwt = jwt_encrypt2($jwt, $encryption_keys[0], false, NULL, $header_params, NULL, $alg, $enc, false);
            if (!$jwt) {
                if ($cryptoError)
                    $cryptoError = 'error_enc';
                log_error("Unable to encrypt %s", $jwt);
                return null;
            }
            log_debug('jwe = %s', $jwt);
        } else {
            $cryptoError  = 'error_enc';
            log_error("encryption algs not supported %s %s", $alg, $enc);
            return null;
        }
    }
    return $jwt;
}

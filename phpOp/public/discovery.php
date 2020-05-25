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
require_once('../libdb2.php');
include_once('../logging.php');

error_reporting(E_ERROR | E_WARNING | E_PARSE);
logw_debug("Request: %s\nInput: %s", count($_REQUEST) ? print_r($_REQUEST, true) : '[ ]', file_get_contents('php://input'));


if (strpos($_SERVER['REQUEST_URI'], '/.well-known/openid-configuration') !== false) {
    handle_openid_config();
} elseif (strpos($_SERVER['REQUEST_URI'], '/.well-known/webfinger') !== false)
    handle_webfinger_discovery();
exit;


function handle_openid_config()
{
    global $signing_alg_values_supported, $encryption_alg_values_supported, $encryption_enc_values_supported, $config;
    $endpoint_base =  OP_INDEX_PAGE;
    $op_url = $config['OP']['op_url'];
    $discovery = array(
        'version' => '3.0',
        'issuer' => $op_url,
        'authorization_endpoint' => OP_AUTH_EP,
        'token_endpoint' => OP_TOKEN_EP,
        'userinfo_endpoint' => OP_USERINFO_EP,
        'check_session_iframe' => $op_url . '/opframe.php',
        'end_session_endpoint' => $endpoint_base . '/endsession',
        'jwks_uri' =>  $config['OP']['jwk_url'],
        'registration_endpoint' => $endpoint_base . '/registration',
        'scopes_supported' => array('openid', 'profile', 'email', 'address', 'phone', 'offline_access'),
        'response_types_supported' => array('code', 'code token', 'code id_token', 'token', 'id_token token', 'code id_token token', 'id_token'),
        'grant_types_supported' => array('authorization_code', 'implicit'),
        //                        'acr_values_supported' => Array('http://www.idmanagement.gov/schema/2009/05/icam/openid-trust-level1.pdf'),
        'acr_values_supported' => array(),
        'subject_types_supported' => array('public', 'pairwise'),

        'userinfo_signing_alg_values_supported' => $signing_alg_values_supported,
        'userinfo_encryption_alg_values_supported' => $encryption_alg_values_supported,
        'userinfo_encryption_enc_values_supported' => $encryption_enc_values_supported,

        'id_token_signing_alg_values_supported' => $signing_alg_values_supported,
        'id_token_encryption_alg_values_supported' => $encryption_alg_values_supported,
        'id_token_encryption_enc_values_supported' => $encryption_enc_values_supported,

        'request_object_signing_alg_values_supported' => $signing_alg_values_supported,
        'request_object_encryption_alg_values_supported' => $encryption_alg_values_supported,
        'request_object_encryption_enc_values_supported' => $encryption_enc_values_supported,

        'token_endpoint_auth_methods_supported' => array('client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt'),
        'token_endpoint_auth_signing_alg_values_supported' => $signing_alg_values_supported,

        'display_values_supported' => array('page'),
        'claim_types_supported' => array('normal'),
        'claims_supported' => array('name', 'given_name', 'family_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'email', 'email_verified', 'gender', 'birthdate', 'zoneinfo', 'locale', 'phone_number', 'phone_number_verified', 'address', 'updated_at'),
        'service_documentation' => $endpoint_base . '/servicedocs',

        'claims_locales_supported' => array('en-US'),
        'ui_locales_supported' => array('en-US'),
        'require_request_uri_registration' => false,
        'op_policy_uri' => $endpoint_base . '/op_policy',
        'op_tos_uri' => $endpoint_base . '/op_tos',

        'claims_parameter_supported' => true,
        'request_parameter_supported' => true,
        'request_uri_parameter_supported' => true
    );

    header('Content-Type: application/json');
    echo pretty_json(json_encode($discovery));
}




function send_webfinger_discovery($subject = NULL)
{
    global $config;
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/jrd+json');

    $hostmeta = array();
    if ($subject)
        $hostmeta['subject'] = $subject;

    $hostmeta = array_merge(
        $hostmeta,
        array(
            'links' => array(
                array(
                    'rel' => 'http://openid.net/specs/connect/1.0/issuer',
                    'href' => $config['OP']['op_url']
                )
            )
        )
    );
    echo json_encode($hostmeta);
}


function handle_webfinger_discovery()
{
    global $config;
    $principal = $_REQUEST['resource'];
    $service = $_REQUEST['rel'];
    if (!$principal && !$service) {
        log_error('Discovery : no principal or service');
        header('HTTP/1.0 400 Bad Request');
        exit;
    }
    if ($service && $service != 'http://openid.net/specs/connect/1.0/issuer') {
        log_error('Discovery : invalid service');
        header('HTTP/1.0 400 Bad Request');
        exit;
    }
    $op_url = $config['OP']['op_url'];
    $url_info = parse_url($op_url);
    $base_url = $url_info["scheme"] . '://' . $url_info["host"] . (array_key_exists('port', $url_info) ? ':'.$url_info['port'] : '');

    // $hosts = array($config['OP']['op_server_name'], OP_PROTOCOL . OP_SERVER_NAME, OP_PROTOCOL . OP_SERVER_NAME . OP_PORT, $op_url);
    $hosts = array($config['OP']['op_server_name'], $base_url, $op_url);

    if ($principal && substr($principal, 0, 5) == 'acct:')
        $principal = substr($principal, 5);

    $at = strpos($principal, '@');
    if ($at !== false) {
        if ($at == 0) {    // XRI
            header('HTTP/1.0 400 Bad Request');
            log_error('Discovery : principal is a XRI');
            exit;
        }
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
        for ($i = $domain_start, $j = $server_start; $i >= 0 && $j >= 0; $i--, $j--) {
            if (strcasecmp($domain_parts[$i], $server_parts[$j]) != 0) {
                header('HTTP/1.0 400 Bad Request');
                log_error('Discovery : email domains do not match');
                exit;
            }
        }
    } else { // process URL
        $pos = strpos($principal, '#');
        if ($pos !== false)
            $principal = substr($principal, 0, $pos);
        $parts = parse_url($principal);
        if (!$parts) {
            log_error('Discovery : unparseable URL');
            header('HTTP/1.0 400 Bad Request');
            exit;
        }
        $host = $parts['host'];
        $port = $parts['port'] ? ':' . $parts['port'] : '';
        $issuer = $parts['scheme'] . '://' . $host . $port;
        if (isset($parts['path'])) {
            if ($parts['path'] == '/')
                $principal = $issuer;
            else if ($parts['path'] == $config['OP']['path']) // OP Issuer Path
                $principal = $config['OP']['op_url'];
            else {
                $principal = substr($parts['path'], 1);
                log_debug("principal = %s", $principal);
            }
        } else {
            $principal = $issuer;
        }
    }

    if (!in_array($principal, $hosts) && !db_get_user($principal)) {
        log_error("Discovery : no such user or host\nprincipal = %s hosts = %s", $principal, print_r($hosts, true));
        header('HTTP/1.0 400 Bad Request');
        exit;
    }
    send_webfinger_discovery($_REQUEST['resource']);
}

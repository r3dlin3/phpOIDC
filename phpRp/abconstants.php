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

/*
* Specifies the OP's server name/IP address. By default, it uses what the client uses
*/


if (!defined('RP_SERVER_NAME')) {
    if ($_SERVER['SERVER_NAME'])
        define('RP_SERVER_NAME', $_SERVER['SERVER_NAME']);
    else {
        $pieces = explode(":", $_SERVER['HTTP_HOST']);
        define('RP_SERVER_NAME', $pieces[0]);
    }
}

/*
* Specifies the RP's protocol 
*/
define("RP_PROTOCOL", $_SERVER['REQUEST_SCHEME'] . '://');

/*
* Specifies the RP's protocol port 
* Should use ':port_num' format e.g. :80
*/
$port = '';
if (
    !($_SERVER['REQUEST_SCHEME'] === "http" && $_SERVER['SERVER_PORT'] == 80)
    || !($_SERVER['REQUEST_SCHEME'] === "https" && $_SERVER['SERVER_PORT'] == 443)
) {
    $port = ':' . $_SERVER['SERVER_PORT'];
}
define("RP_PORT", $port);

/*
* Specifies the RP's PATH
* 
*/
// strip the document_root from the script filename and extract the folder
$path = dirname(str_replace($_SERVER['DOCUMENT_ROOT'],'',$_SERVER['SCRIPT_FILENAME']));
define("RP_PATH", $path);

/*
* Specifies the RP's URL
* 
*/
define("RP_URL", RP_PROTOCOL . RP_SERVER_NAME . RP_PORT . RP_PATH);

/**
* path to the RP's private key for signing
*/
define("RP_SIG_PKEY", dirname($_SERVER['SCRIPT_FILENAME']) . "/rp/rp_sig.key");

/**
* RP's pass phrase for the private key file for signing
*/
define("RP_SIG_PKEY_PASSPHRASE","");

/**
 * path to the RP's private key for encryption
 */
define("RP_ENC_PKEY", dirname($_SERVER['SCRIPT_FILENAME']) . "/rp/rp_enc.key");

/**
 * RP's pass phrase for the private key file for encryption
 */
define("RP_ENC_PKEY_PASSPHRASE","");

/**
* URL to RP's public JWK
*/
define("RP_JWK_URL", RP_URL . '/rp/rp.jwk');

/**
* RP's Signature Kid
*/
define("RP_SIG_KID", 'PHPRP-00S');

/**
* RP's Encryption Kid
*/
define("RP_ENC_KID", 'PHPRP-00E');


/**
* RP endpoints and Metadata
*
*/
define('RP_INDEX_PAGE', RP_URL . '/index.php');
define('RP_REDIRECT_URI', RP_INDEX_PAGE . '/callback');
define('RP_AUTHCHECK_REDIRECT_URI', RP_URL . '/authcheck.php/authcheckcb');
define('RP_POST_LOGOUT_REDIRECT_URI', RP_INDEX_PAGE . '/logoutcb');
define('RP_CLIENT_ID', RP_URL . '/');

define('ENABLE_PKCE', 0);

?>
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
require_once(__DIR__ . '/libs/autoload.php');

define("LOGFILE", __DIR__ . '/app.log');
define("LOGLEVEL", 'DEBUG');


/**
 * Name of the theme
 */
define("THEME_NAME", "default");

/**
 * Root path to theme files
 */
define("THEME_PATH", __DIR__ . '/theme/' . THEME_NAME);
define("THEME_URI",dirname($_SERVER['SCRIPT_NAME']) . '/theme/' . THEME_NAME);

/**
 * Path to view files. Used by Twig.
 */
define("VIEWS_PATH", THEME_PATH . "/views");


/**
 * Path to cache. Used by Twig.
 */
define("CACHE_PATH", __DIR__ . '/cache');


/*
* Specifies the OP's server name/IP address. By default, it uses what the client uses
*/
if (!defined('OP_SERVER_NAME'))
    define('OP_SERVER_NAME', $_SERVER['SERVER_NAME']);





/*
* Specifies the OP's protocol
*/
define("OP_PROTOCOL", 'http://');

/*
* Specifies the OP's protocol port 
* Should use ':port_num' format, e.g. :80
*/
define("OP_PORT", ':8080');

/*
* Specifies the OP's PATH
* 
*/
define("OP_PATH", '/' . basename(dirname($_SERVER['SCRIPT_FILENAME'])));


/*
* Specifies the OP's URL
* 
*/
define("OP_URL", OP_PROTOCOL . OP_SERVER_NAME . OP_PORT . OP_PATH);


$site = [
    "name" => OP_SERVER_NAME,
    "url" => OP_URL
];

$loader = new \Twig\Loader\FilesystemLoader(VIEWS_PATH);
$twig = new \Twig\Environment($loader, [
    'cache' => CACHE_PATH,
]);
$twig->addGlobal('site', $site);
/**
 * path to the OP's private key for signing
 */
define("OP_SIG_PKEY", dirname($_SERVER['SCRIPT_FILENAME']) . "/op_sig.key");

/**
 * OP's pass phrase for the private key file 
 */
define("OP_SIG_PKEY_PASSPHRASE", "");


/**
 * path to the OP's private key for encryption
 */
define("OP_ENC_PKEY", dirname($_SERVER['SCRIPT_FILENAME']) . "/op_enc.key");

/**
 * OP's pass phrase for the private key file
 */
define("OP_ENC_PKEY_PASSPHRASE", "");

/**
 * URL to OP's public JWK
 */
define("OP_JWK_URL", OP_URL . '/op.jwk');

/**
 * OP's Signature Kid
 */
define("OP_SIG_KID", 'PHPOP-00S');

/**
 * OP's Encryption Kid
 */
define("OP_ENC_KID", 'PHPOP-00E');


/**
 * OP endpoints and metadata
 *
 */
define('OP_INDEX_PAGE', OP_URL . '/index.php');
define('OP_AUTH_EP', OP_INDEX_PAGE . '/auth');
define('OP_TOKEN_EP', OP_INDEX_PAGE . '/token');
define('OP_USERINFO_EP', OP_INDEX_PAGE . '/userinfo');
define('OP_CHECKSESSION_EP', OP_INDEX_PAGE . '/checksession');
define('OP_SESSIONINFO_EP', OP_INDEX_PAGE . '/sessioninfo');

define('ENABLE_PKCE', 0);

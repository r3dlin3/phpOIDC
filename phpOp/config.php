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

use eftec\bladeone\BladeOne;


// Load .env
if (file_exists(__DIR__ . '/.env')) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
    $dotenv->load();
}


$theme_name = getenv('THEME_NAME') ?: 'default';

// $op_server_name can be set by:
// - Env var (OP_SERVER_NAME)
// - the server name (coming from $_SERVER['SERVER_NAME'])
// - from the request itself ($_SERVER['HTTP_HOST']). Not secured. But this is a configuration
// for testing purpose. It is recommended to be set the OP_URL environment variable.
if (getenv('OP_SERVER_NAME')) {
    $op_server_name = getenv('OP_SERVER_NAME');
} else {
    if ($_SERVER['SERVER_NAME'])
    $op_server_name = $_SERVER['SERVER_NAME'];
    else {
        $pieces = explode(":", $_SERVER['HTTP_HOST']);
        $op_server_name = $pieces[0];
    }
}

// variables to construct OP_URL
$scheme = isset($_SERVER['REQUEST_SCHEME']) ? $_SERVER['REQUEST_SCHEME'] : 
    (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http");

$protocol = $scheme . '://';
$port = '';
if (
    !($scheme === "http" && $_SERVER['SERVER_PORT'] == 80)
    && !($scheme === "https" && $_SERVER['SERVER_PORT'] == 443)
) {
    $port = ':' . $_SERVER['SERVER_PORT'];
}
$path = getenv('OP_URL') ? parse_url(getenv('OP_URL'))['path'] : (array_key_exists('OP_PATH', $_ENV) ? getenv('OP_PATH') : '/phpOp');
define("OP_PATH", rtrim($path, '/'));
$op_url = getenv('OP_URL') ?: ($protocol . $op_server_name . $port . $path);
$op_url = rtrim($op_url, "/");

/**
 * OP endpoints and metadata
 */
define('OP_INDEX_PAGE', $op_url . '/index.php');
define('OP_AUTH_EP', OP_INDEX_PAGE . '/auth');
define('OP_TOKEN_EP', OP_INDEX_PAGE . '/token');
define('OP_USERINFO_EP', OP_INDEX_PAGE . '/userinfo');
define('OP_CHECKSESSION_EP', OP_INDEX_PAGE . '/checksession');
define('OP_SESSIONINFO_EP', OP_INDEX_PAGE . '/sessioninfo');
define('OP_REGISTRATION_FORM_EP', OP_INDEX_PAGE . '/register_form');
define('OP_REGISTRATION_EP', OP_INDEX_PAGE . '/register');
define('OP_REGISTRATION_CONTINUE_EP', OP_INDEX_PAGE . '/register_continue');
define('OP_PASSWORD_RESET_EP', OP_INDEX_PAGE . '/forgotpassword_form');
define('OP_PASSWORD_RESET_CONTINUE_EP', OP_INDEX_PAGE . '/forgotpassword');
define('OP_PASSWORD_RESET_CODE_EP', OP_INDEX_PAGE . '/passwordreset/');
define('OP_PASSWORD_RESET_CODE_CONTINUE_EP', OP_INDEX_PAGE . '/passwordreset');
define('OP_LOGIN_EP', OP_INDEX_PAGE . '/login');
define('OP_SOCIALITE_EP', OP_INDEX_PAGE . '/socialite/');
define('OP_SOCIALITE_REDIRECT_EP', OP_INDEX_PAGE . '/socialitecb/');

/**
 * Global config
 */
$config = [
    'site' => [
        'theme_name' => $theme_name,
        'theme_uri' => getenv('THEME_URI') ?: (OP_PATH . '/theme/' . $theme_name),
        'views_path' => getenv('VIEWS_PATH') ?:  __DIR__ . '/views/' . $theme_name,
        'name' => getenv('SITE_NAME') ?: $op_server_name,
        "url" => $op_url,
        'enable_password_reset' =>  array_key_exists('ENABLE_PASSWORD_RESET', $_ENV) ? (getenv('ENABLE_PASSWORD_RESET') === 'true') : true,
        'password_reset_url' => getenv('PASSWORD_RESET_URL') ?: OP_PASSWORD_RESET_EP,
        'enable_registration' => array_key_exists('ENABLE_REGISTRATION', $_ENV) ? (getenv('ENABLE_REGISTRATION') === 'true') : true,
        'registration_url' => getenv('REGISTRATION_URL') ?: OP_REGISTRATION_FORM_EP,
        'enable_admin' => array_key_exists('ENABLE_ADMIN', $_ENV) ? (getenv('ENABLE_ADMIN') === 'true') : true,
        'enable_dynamic_client_registration' => array_key_exists('ENABLE_DYNAMIC_CLIENT_REGISTRATION', $_ENV) ? (getenv('ENABLE_DYNAMIC_CLIENT_REGISTRATION') === 'true') : true,
    ],

    'blade' => [
        'cache' => getenv('BLADE_CACHE') ?: (__DIR__ . '/cache'),
    ],

    'OP' => [
        'op_server_name' => $op_server_name,
        'op_url' => $op_url,
        'enable_pkce' => getenv('ENABLE_PKCE') ?: false,
        'path' => $path,
        'sig_pkey' => getenv('OP_SIG_PKEY') ?:  __DIR__ . '/op/op_sig.key',
        'sig_pkey_passphrase' => getenv('OP_SIG_PKEY_PASSPHRASE') ?:  '',
        'enc_pkey' => getenv('OP_ENC_PKEY') ?:  __DIR__ . '/op/op_enc.key',
        'enc_pkey_passphrase' => getenv('OP_ENC_PKEY_PASSPHRASE') ?:  '',
        'jwk_url' => getenv('OP_JWK_URL') ?:  $op_url . '/op.jwk',
        'sig_kid' => getenv('OP_SIG_KID') ?:  'PHPOP-00S',
        'enc_kid' => getenv('OP_ENC_KID') ?:  'PHPOP-00E',
    ],

    'DB' => [
        'type' => getenv('DB_TYPE') ?: 'mysql',
        'user' => getenv('DB_USER') ?: 'root',
        'password' => getenv('DB_PASSWORD') ?: '',
        'host' => getenv('DB_HOST') ?: 'localhost',
        'port' => getenv('DB_HOST') ?: '3306',
        'database' => getenv('DB_DATABASE') ?: 'phpoidc'
    ],

    'mail' => [
        'transport' => getenv('MAIL_TRANSPORT') ?: 'mail',
        'host' => getenv('MAIL_HOST') ?: null,
        'auth' => array_key_exists('MAIL_AUTH', $_ENV) ? (getenv('MAIL_HOST') === 'true') : true,
        'user' => getenv('MAIL_USER') ?: null,
        'password' => getenv('MAIL_PASSWORD') ?: null,
        'port' => getenv('MAIL_PORT') ?: null,
        'encryption' => getenv('MAIL_ENCRYPTION') ?: '',
        'smtp' => getenv('MAIL_SMTP') ?: null,
        'from' => getenv('MAIL_FROM') ?: null,
        'reply_to' => getenv('MAIL_REPLY_TO') ?: null,
        'auto_tls' => array_key_exists('MAIL_SMTP_AUTO_TLS', $_ENV) ? (getenv('MAIL_HOST') === 'true') : false,
    ],
    'socialite' => [
        'bitbucket' => [
            'client_id' => getenv('BITBUCKET_CLIENT_ID') ?: null,
            'client_secret' => getenv('BITBUCKET_CLIENT_SECRET') ?: null,
            'redirect' => getenv('BITBUCKET_REDIRECT_URL') ?: OP_SOCIALITE_REDIRECT_EP.'bitbucket/',
        ],
        'facebook' => [
            'client_id' => getenv('FACEBOOK_CLIENT_ID') ?: null,
            'client_secret' => getenv('FACEBOOK_CLIENT_SECRET') ?: null,
            'redirect' => getenv('FACEBOOK_REDIRECT_URL') ?: OP_SOCIALITE_REDIRECT_EP.'facebook/',
        ],
        'github' => [
            'client_id' => getenv('GITHUB_CLIENT_ID') ?: null,
            'client_secret' => getenv('GITHUB_CLIENT_SECRET') ?: null,
            'redirect' => getenv('GITHUB_REDIRECT_URL') ?: OP_SOCIALITE_REDIRECT_EP.'github/',
        ],
        'gitlab' => [
            'client_id' => getenv('GITLAB_CLIENT_ID') ?: null,
            'client_secret' => getenv('GITLAB_CLIENT_SECRET') ?: null,
            'redirect' => getenv('GITLAB_REDIRECT_URL') ?: OP_SOCIALITE_REDIRECT_EP.'gitlab/',
        ],
        'linkedin' => [
            'client_id' => getenv('LINKEDIN_CLIENT_ID') ?: null,
            'client_secret' => getenv('LINKEDIN_CLIENT_SECRET') ?: null,
            'redirect' => getenv('LINKEDIN_REDIRECT_URL') ?: OP_SOCIALITE_REDIRECT_EP.'linkedin/',
        ],
        'twitter' => [
            'client_id' => getenv('TWITTER_CLIENT_ID') ?: null,
            'client_secret' => getenv('TWITTER_CLIENT_SECRET') ?: null,
            'redirect' => getenv('TWITTER_REDIRECT_URL') ?: OP_SOCIALITE_REDIRECT_EP.'twitter/',
        ],
        'google' => [
            'client_id' => getenv('GOOGLE_CLIENT_ID') ?: null,
            'client_secret' => getenv('GOOGLE_CLIENT_SECRET') ?: null,
            'redirect' => getenv('GOOGLE_REDIRECT_URL') ?: OP_SOCIALITE_REDIRECT_EP.'google/',
        ]

    ]
];

$is_socialite_enabled = false;
foreach ($config['socialite'] as &$provider_config) {
    if (
        isset($provider_config['client_id'])
        && isset($provider_config['client_secret'])
    ) {
        $is_socialite_enabled = true;
        $provider_config['enable'] = true;
    } else {
        $provider_config['enable'] = false;
    }
}

$config['site']['enable_social_login']
    = array_key_exists('ENABLE_SOCIAL_LOGIN', $_ENV) ? (getenv('ENABLE_SOCIAL_LOGIN') === 'true') : $is_socialite_enabled;

/**
 * I18n
 */

// create the accept factory
$accept_factory = new Aura\Accept\AcceptFactory($_SERVER);

// factory the accept object
$accept = $accept_factory->newInstance();

// language negotiation
$available_languages = array('en', 'fr');
$language = $accept->negotiateLanguage($available_languages);
$locale = $language->getValue();
if (!$locale)
    $locale = 'en';
// Set language
include __DIR__ . '/locales/' . $locale . '.php';

$blade = new BladeOne($config['site']['views_path'], $config['blade']['cache'], BladeOne::MODE_AUTO);
$blade->missingLog='./missingkey.txt'; // (optional) if a traduction is missing the it will be saved here.

$blade->share('site', $config['site']);

$register_form = require_once(__DIR__ . '/register_form.php');
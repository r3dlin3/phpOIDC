<?php

/**
 * MySQL db settings
 */

define('DB_TYPE',               'mysql');
define('DB_USER',               'root');
define('DB_PASSWORD',           '');
define('DB_HOST',               'localhost');
define('DB_PORT',               '3306');
define('DB_DATABASE',           'phpoidc_01');
define('DB_CONNECTION_NAME',    'phpoidc_connection');


define("DSN", DB_TYPE . '://' . DB_USER . ':' . DB_PASSWORD . '@' . DB_HOST . ':' . DB_PORT . '/' . DB_DATABASE );
define('DB_CONNECTION',    Doctrine_Manager::connection(DSN, DB_CONNECTION_NAME));
?>

<?php
include_once(__DIR__ . '/../../../config.php');
include_once(__DIR__ . '/../../../Controller/Response.php');
include_once(__DIR__ . '/../../../Controller/UserController.php');
include_once('../../../logging.php');
error_reporting(E_ERROR | E_WARNING | E_PARSE);

// check admin enabled
if (!$config['site']['enable_admin']) {
    http_response_code(403);
    exit;
}

header("Access-Control-Allow-Origin: " . $config['site']['admin_cors']);
header("Access-Control-Allow-Methods: OPTIONS,GET,POST,PUT,DELETE");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

$request_method = $_SERVER['REQUEST_METHOD'];
if ($request_method === 'OPTIONS') {
    exit;
}

$path_info = array_key_exists('PATH_INFO', $_SERVER) ? $_SERVER['PATH_INFO'] : "/";
$uri = explode('/', $path_info);

function getQueryParams($queryString)
{
    $parameters = [];
    $explodedQueryString = explode('&', $queryString);
    foreach ($explodedQueryString as $string) {
        $values = explode('=', $string);
        $key = $values[0];
        $val = $values[1];
        $parameters[$key] = $val;
    }
    return $parameters;
}


switch ($uri[1]) {
    case 'users':
        $user_controller = new Controller\UserController();
        switch ($request_method) {
            case 'GET':
                $params = getQueryParams($_SERVER['QUERY_STRING']);
                $response = $user_controller->getAllUsers($params);
                break;
            default:
                $response = new Controller\NotFound();
        }
        break;
    default:
        $response = new Controller\NotFound();
}
header($response->content_type);
http_response_code($response->status_code);
$body = $response->get_body();
if ($body) {
    echo $body;
}

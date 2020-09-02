<?php
include_once(__DIR__ . '/../../../config.php');
require __DIR__ . '/../../../libs/autoload.php';
include_once('../../../logging.php');
error_reporting(E_ERROR | E_WARNING | E_PARSE);

// check admin enabled
if (!$config['site']['enable_admin']) {
    http_response_code(403);
    exit;
}

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use PhpOidc\PhpOp\Api\Controller\PreflightAction;


$request = Laminas\Diactoros\ServerRequestFactory::fromGlobals(
    $_SERVER,
    $_GET,
    $_POST,
    $_COOKIE,
    $_FILES
);
$baseUrl = $_SERVER['SCRIPT_NAME'];

$responseFactory = new \Laminas\Diactoros\ResponseFactory();

$jsonStrategy = new \League\Route\Strategy\JsonStrategy($responseFactory);
$appStrategy = new \PhpOidc\PhpOp\Api\ApplicationStrategy($responseFactory);
$router   = (new League\Route\Router)->setStrategy($appStrategy);
// $router = new \League\Route\Router;

$router->middleware(new PhpOidc\PhpOp\Api\Middleware\AuthMiddleware);
$router->middleware(new PhpOidc\PhpOp\Api\Middleware\CorsMiddleware);

$router
    ->group($baseUrl . '/users', function (\League\Route\RouteGroup $route) {
        $route->map('GET', '/', 'PhpOidc\PhpOp\Api\Controller\UserController::getAllUsers');
        $route->map('OPTIONS', '/', PreflightAction::class);
        $route->map('GET', '/{id:number}', 'PhpOidc\PhpOp\Api\Controller\UserController::getUser');
        $route->map('OPTIONS', '/{id:number}', PreflightAction::class);
    })
    ->setStrategy($jsonStrategy);


$response = $router->dispatch($request);

// send the response to the browser
(new \Laminas\HttpHandlerRunner\Emitter\SapiEmitter)->emit($response);

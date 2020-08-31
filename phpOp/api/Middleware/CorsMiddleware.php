<?php

declare(strict_types=1);

namespace PhpOidc\PhpOp\Api\Middleware;

require __DIR__ . '/../../libs/autoload.php';
include_once(__DIR__ . '/../../config.php');

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Diactoros\Response;


class CorsMiddleware implements MiddlewareInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        global $config;
        $headers = [
            "Access-Control-Allow-Origin" => $config['site']['admin_cors'],
            "Access-Control-Allow-Methods" => "OPTIONS,GET,POST,PUT,DELETE",
            "Access-Control-Max-Age" => "3600",
            "Access-Control-Allow-Headers" => "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With"
        ];

        $response = $handler->handle($request);
        foreach ($headers as $header => $value) {
            $response = $response->withHeader($header, $value);
        }
        return $response;
    }
}

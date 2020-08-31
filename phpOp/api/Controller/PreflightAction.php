<?php

namespace PhpOidc\PhpOp\Api\Controller;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class PreflightAction
{
    public function __invoke(
        ServerRequestInterface $request
    ): ResponseInterface {
        $response = new \Laminas\Diactoros\Response;
        return $response;
    }
}

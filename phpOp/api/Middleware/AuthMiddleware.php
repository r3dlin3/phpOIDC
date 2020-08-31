<?php

declare(strict_types=1);

namespace PhpOidc\PhpOp\Api\Middleware;

require __DIR__ . '/../../libs/autoload.php';
include_once(__DIR__ . '/../../config.php');
include_once(__DIR__ . '/../../libdb2.php');

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Diactoros\Response;
use League\Route\Http\Exception\{UnauthorizedException, ForbiddenException};

/**
 * Middleware to validate access token
 * TODO: implement cache
 */
class AuthMiddleware implements MiddlewareInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        global $config;
        if ($request->getMethod() === 'OPTIONS') {
            // No auth
            return $handler->handle($request);
        }
        $realm = "phpoidc";

        $access_token = "";

        if (preg_match("/Bearer\s+(.*)$/i", $request->getHeaderLine("Authorization"), $matches)) {
            $access_token = $matches[1];
        }

        if (!$access_token) {
            throw new UnauthorizedException();
            /*
            $response = (new Response())
                ->withStatus(401)
                ->withHeader(
                    "WWW-Authenticate",
                    sprintf('Basic realm="%s"', $realm)
                );
                */
        }

        $token = db_find_access_token($access_token);
        if (!$token) {
            // Token not found
            throw new UnauthorizedException();
        }
        // XXX: validate token validity (not implemented in validatetoken endpoint)
        $tinfo = json_decode($token['info'], true);
        $db_user = db_get_user($tinfo['u']);

        if ($db_user && $db_user['enabled']) {
            if (in_array($tinfo['u'], $config['site']['admins'])) {
                return $handler->handle($request);
            } else {
                throw new ForbiddenException();
            }
        }

        throw new UnauthorizedException();
    }
}

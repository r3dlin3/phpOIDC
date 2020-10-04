<?php

namespace PhpOidc\PhpOp\Api\Controller;

include_once(__DIR__ . '/../../libs/autoload.php');
include_once(__DIR__ . '/../../libdb2.php');
require_once __DIR__ . '/../../PasswordHash.php';

use Laminas\Diactoros\Response;
use League\Route\Http\Exception\{NotFoundException, BadRequestException};
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Validator as v;

use JsonException;
use Token;
use PhpOidc\PhpOp\Api\Response\{ProblemDetails, PaginatedResultResponse};


class UserTokenController
{

    private function map_token(Token $token): array
    {
        $info = json_decode($token->getInfo(), true);
        $res = [
            "id" => $token->getId(),
            "account_id" => $token->getAccountId(),
            "token_type" => $token->getTokenType(),
            "client" => $token->getClient(),
            "issued_at" => $token->getIssuedAt()->format(\DateTime::ATOM),
            "expiration_at" => $token->getExpirationAt()->format(\DateTime::ATOM),
            "scope" => $info['g']['scope']
        ];
        return $res;
    }

    function list(ServerRequestInterface $request, $args)
    {
        $validator = v::key('id', v::finite()->positive());
        $validator->assert($args);

        $id = $args['id'];
        $tokens = db_get_user_tokens_by_user_id($id);
        if ($tokens == null) {
            $tokens = [];
        }

        $result = array_map(array('PhpOidc\PhpOp\Api\Controller\UserTokenController', 'map_token'), $tokens);
        return new PaginatedResultResponse($result, count($tokens), 0);
    }

    function show(ServerRequestInterface $request, $args)
    {
        $validator = v::key('id', v::finite()->positive());
        $validator->assert($args);

        $id = $args['id'];
        $user = db_get_account_by_id($id);
        if (!$user) {
            throw new NotFoundException();
        }
        return $this->map_user($user);
    }

    function update(ServerRequestInterface $request, array $args)
    {
        $validator = v::key('id', v::finite()->positive());
        $validator->assert($args);

        $id = $args['id'];

        try {
            $body = json_decode($request->getBody(), true, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new BadRequestException();
        }

        $req_validator =  v::key('id', v::finite()->positive())
            ->key('enabled', v::boolType(), false)
            ->key('login', v::anyOf(v::alnum(), v::email()), false)
            ->key('name', v::stringType(), false)
            ->key('given_name', v::stringType(), false)
            ->key('family_name', v::stringType(), false)
            ->key('middle_name', v::stringType(), false)
            ->key('nickname', v::stringType(), false)
            ->key('preferred_username', v::stringType(), false)
            ->key('profile', v::url(), false)
            ->key('picture', v::url(), false)
            ->key('website', v::url(), false)
            ->key('email', v::email(), false)
            ->key('email_verified', v::nullable(v::boolType()), false)
            ->key('gender', v::stringType(), false)
            ->key('birthdate', v::date(), false)
            ->key('zoneinfo', v::dateTime('e'), false)
            ->key('locale', v::languageCode(), false)
            ->key('phone_number', v::phone(), false)
            ->key('phone_number_verified', v::boolType(), false)
            ->key('address', v::stringType(), false);

        $req_validator->assert($body);

        if ($id != $body['id'])
            throw new BadRequestException('Invalid id');

        $a = $this->map_request_to_account_array($body);

        if (array_key_exists('password', $body))
            $a['crypted_password'] = create_hash($body['password']);


        $user = db_save_account_by_id($id, $a);
        if (!$user) {
            return new ProblemDetails(
                "http://phpoidc.org/validation-error",
                "Login already exists"
            );
        }
        return $this->map_user($user);
    }

    function delete(ServerRequestInterface $request, array $args)
    {
        $validator = v::key('id', v::finite()->positive());
        $validator->assert($args);

        $id = $args['id'];
        $found = db_delete_account_by_id($id);
        if (!$found) {
            throw new NotFoundException();
        }
        return (new Response())->withStatus(204);
    }
}

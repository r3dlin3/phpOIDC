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

use Account;
use PhpOidc\PhpOp\Api\Response\{ProblemDetails,PaginatedResultResponse};




class UserController
{

    private function map_user(Account $account): array
    {
        $res = $account->toArray();
        // These attributes are excluded from the response
        $secret_attributes = [
            'crypted_password',
            'name_ja_kana_jp',
            'name_ja_hani_jp',
            'given_name_ja_kana_jp',
            'given_name_ja_hani_jp',
            'family_name_ja_kana_jp',
            'family_name_ja_hani_jp',
            'middle_name_ja_kana_jp',
            'middle_name_ja_hani_jp',
            'created_at',
            'reset_password_code',
            'reset_password_code_timeout',
            'offsetMethods',
            'offsetMethodMap',
            'iterator',
            'refreshToken',
            'token',
            'refreshToken',
            'expiresIn'
        ];
        foreach ($secret_attributes as $name) {
            if (array_key_exists($name, $res))
                unset($res[$name]);
        }
        if (array_key_exists('updated_at', $res))
            $res['updated_at'] = $res['updated_at']->format(\DateTime::ATOM);


        return $res;
    }

    private function map_request_to_account_array($values): array
    {
        $attribute_names = [
            'id',
            'enabled',
            'login',
            'name',
            'given_name',
            'family_name',
            'middle_name',
            'nickname',
            'preferred_username',
            'profile',
            'picture',
            'website',
            'email',
            'email_verified',
            'gender',
            'birthdate',
            'zoneinfo',
            'locale',
            'phone_number',
            'phone_number_verified',
            'address'
        ];
        $a = [];
        foreach ($attribute_names as $name) {
            if (array_key_exists($name, $values)) {
                $a[$name] = $values[$name];
            }
        }
        return $a;
    }


    function list(ServerRequestInterface $request)
    {
        $params = $request->getQueryParams();
        $paginatedParamsValidator = v::key('limit', v::finite()->positive(), false)
            ->key('offset', v::finite()->min(0), false)
            ->key('order', v::in(['asc', 'desc']), false)
            ->key('search', v::stringType(), false)
            ->key('sort', v::stringType(), false);

        $paginatedParamsValidator->assert($params);

        $count = db_get_account_count();
        // At this point no limitation on the paginated size
        // This API is dedicated to admin only
        $limit = array_key_exists('limit', $params) ? $params['limit'] : null;
        $offset = array_key_exists('offset', $params) ? $params['offset'] : null;
        $search = array_key_exists('search', $params) ? $params['search'] : null;

        $sort_field = array_key_exists('sort', $params) ? $params['sort'] : null;
        if (!$sort_field) {
            $sort_field = 'login';
        }

        $sort_order = array_key_exists('order', $params) ? $params['order'] : null;
        if (!$sort_order) {
            $sort_order = 'asc';
        }
        // Note: $offset can be equal to "0"
        if (isset($limit) && isset($offset)) {
            $result = db_search_accounts($search, $sort_field, $sort_order, $limit, $offset);
        } else {
            $result = db_search_accounts($search, $sort_field, $sort_order);
        }

        $result = array_map(array('PhpOidc\PhpOp\Api\Controller\UserController', 'map_user'), $result);
        return new PaginatedResultResponse($result, $count, $offset);
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

    function create(ServerRequestInterface $request)
    {
        try {
            $body = json_decode($request->getBody(), true, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new BadRequestException();
        }

        $req_validator = v::key('enabled', v::boolType())
            ->key('login', v::anyOf(v::alnum(), v::email()))
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

        $a = $this->map_request_to_account_array($body);

        if (array_key_exists('password', $body))
            $a['crypted_password'] = create_hash($body['password']);

        $login = $body['login'];

        $user = db_create_account_with_values($login, $a);
        if (!$user) {
            return new ProblemDetails(
                "http://phpoidc.org/validation-error",
                "Login already exists"
            );
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

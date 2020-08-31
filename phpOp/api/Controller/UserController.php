<?php

namespace PhpOidc\PhpOp\Api\Controller;

use Respect\Validation\Validator as v;
use Respect\Validation\Exceptions\NestedValidationException;
use Psr\Http\Message\ServerRequestInterface;

use PhpOidc\PhpOp\Api\ProblemDetails;
use PhpOidc\PhpOp\Api\PaginatedResultResponse;

include_once(__DIR__ . '/../Response.php');
include_once(__DIR__ . '/../../libdb2.php');



class UserController
{

    private function map_user($account)
    {
        return [
            'id' => $account['id'],
            'enabled' => $account['enabled'],
            'login' => $account['login'],
            'name' => $account['name'],
            'given_name' => $account['given_name'],
            'family_name' => $account['family_name'],
            'middle_name' => $account['middle_name'],
            'nickname' => $account['nickname'],
            'preferred_username' => $account['preferred_username'],
            'profile' => $account['profile'],
            'picture' => $account['picture'],
            'website' => $account['website'],
            'email' => $account['email'],
            'email_verified' => $account['email_verified'],
            'gender' => $account['gender'],
            'birthdate' => $account['birthdate'],
            'zoneinfo' => $account['zoneinfo'],
            'locale' => $account['locale'],
            'phone_number' => $account['phone_number'],
            'phone_number_verified' => $account['phone_number_verified'],
            'address' => $account['address'],
            'updated_at' => $account['updated_at']->format(\DateTime::ATOM)
        ];
    }

    function getAllUsers(ServerRequestInterface $request)
    {
        $params = $request->getQueryParams();
        $paginatedParamsValidator = v::key('limit', v::finite()->positive(), false)
            ->key('offset', v::finite()->min(0), false)
            ->key('order', v::in(['asc', 'desc']), false)
            ->key('search', v::stringType(), false)
            ->key('sort', v::stringType(), false);

        try {
            $paginatedParamsValidator->assert($params);
        } catch (NestedValidationException $exception) {
            return new ProblemDetails(
                "http://phpoidc.org/validation-error",
                "Invalid parameters",
                $exception->getFullMessage()
            );
        }

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

    function getUser(ServerRequestInterface $request, array $args)
    {
        $id = $args['id'];
    }
}

<?php

namespace Controller;

use Respect\Validation\Validator as v;
use Respect\Validation\Exceptions\NestedValidationException;

include_once('Response.php');
include(__DIR__ . '/../libdb2.php');



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

    function getAllUsers($params)
    {
        $paginatedParamsValidator = v::key('limit', v::finite()->positive())
            ->key('offset', v::finite()->min(0))
            ->key('order', v::in(['asc', 'desc']), false)
            ->key('search', v::stringType(), false)
            ->key('sort', v::stringType(), false);

        try {
            $paginatedParamsValidator->assert($params);
        } catch (NestedValidationException $exception) {
            return new \Controller\ProblemDetails(
                "http://phpoidc.org/validation-error",
                "Invalid parameters",
                $exception->getFullMessage()
            );
        }

        $count = db_get_account_count();
        // At this point no limitation on the paginated size
        // This API is dedicated to admin only
        $limit = $params['limit'];
        $offset = $params['offset'];

        $sort_field = $params['sort'];
        if (!$sort_field) {
            $sort_field = 'login';
        }

        $sort_order = $params['order'];
        if (!$sort_order) {
            $sort_order = 'asc';
        }
        // Note: $offset can be equal to "0"
        if (isset($limit) && isset($offset)) {
            $result = db_search_accounts($params['search'], $sort_field, $sort_order, $limit, $offset);
        } else {
            $result = db_search_accounts($params['search'], $sort_field, $sort_order);
        }
        
        $result = array_map(array('Controller\UserController', 'map_user'), $result);
        return new PaginatedResultResponse($result, $count, $offset);
    }
}

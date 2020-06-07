<?php

namespace Laravel\Socialite\Two;

use Illuminate\Support\Arr;
use Laravel\Socialite\Contracts\Provider as ProviderInterface;
use Account;

class GoogleProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'openid',
        'profile',
        'email',
    ];

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://accounts.google.com/o/oauth2/auth', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://www.googleapis.com/oauth2/v4/token';
    }

    /**
     * Get the POST fields for the token request.
     *
     * @param  string  $code
     * @return array
     */
    protected function getTokenFields($code)
    {
        return Arr::add(
            parent::getTokenFields($code), 'grant_type', 'authorization_code'
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get('https://www.googleapis.com/oauth2/v3/userinfo', [
            'query' => [
                'prettyPrint' => 'false',
            ],
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new Account)->setRaw($user)->map([
            'login' => 'google' . Arr::get($user, 'sub'), // uniquely identify the user
            'name' => Arr::get($user, 'name'),
            'given_name' => Arr::get($user, 'given_name'),
            'family_name' => Arr::get($user, 'family_name'),
            'picture' => Arr::get($user, 'picture'),
            'email' => Arr::get($user, 'email'),
            'email_verified' => Arr::get($user, 'email_verified'),
            'locale' => Arr::get($user, 'locale'),
        ]);
    }
}

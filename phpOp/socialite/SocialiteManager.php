<?php

namespace Laravel\Socialite;

use Illuminate\Support\Arr;
use InvalidArgumentException;
use Laravel\Socialite\One\TwitterProvider;
use Laravel\Socialite\Two\BitbucketProvider;
use Laravel\Socialite\Two\FacebookProvider;
use Laravel\Socialite\Two\GithubProvider;
use Laravel\Socialite\Two\GitlabProvider;
use Laravel\Socialite\Two\GoogleProvider;
use Laravel\Socialite\Two\LinkedInProvider;
use League\OAuth1\Client\Server\Twitter as TwitterServer;

class SocialiteManager implements Contracts\Factory
{

    /**
     * Build an OAuth 2 provider instance.
     *
     * @param  string  $provider
     * @param  array  $config
     * @return \Laravel\Socialite\Contracts\Provider
     */
    public static function driver($provider, $socialiteconfig)
    {
        $class_name = 'Laravel\Socialite\Two\\' . ucwords($provider) . 'Provider';

        if (!class_exists($class_name)) {
            throw new \Exception('Invalid provider name: '. $provider);
        }
        $config  = $socialiteconfig[strtolower($provider)];

        if (!isset($config) || !$config['enable']) {
            throw new \Exception("Provider $provider is disabled");
        }

        return new $class_name(
            $config['client_id'],
            $config['client_secret'],
            Arr::get($config, 'redirect'),
            Arr::get($config, 'guzzle', [])
        );
    }


    /**
     * Format the server configuration.
     *
     * @param  array  $config
     * @return array
     */
    public function formatConfig(array $config)
    {
        return array_merge([
            'identifier' => $config['client_id'],
            'secret' => $config['client_secret'],
            'callback_uri' => $this->formatRedirectUrl($config),
        ], $config);
    }

}

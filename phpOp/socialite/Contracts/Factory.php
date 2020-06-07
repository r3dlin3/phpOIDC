<?php

namespace Laravel\Socialite\Contracts;

interface Factory
{
    /**
     * Get an OAuth provider implementation.
     *
     * @param  string  $driver
     * @param  array  $config
     * @return \Laravel\Socialite\Contracts\Provider
     */
    public static function driver($provider, $socialiteconfig);
}

<?php

namespace Helper;

// here you can define custom actions
// all public methods declared in helper class will be available in $I

class Api extends \Codeception\Module
{
    /**
     * Get current url from WebDriver
     * @return mixed
     * @throws \Codeception\Exception\ModuleException
     */
    public function getCurrentUrl()
    {
        return $this->getModule('REST')->_getConfig('url');
    }

    /**
     * Toggle redirections on and off.
     *
     * By default, BrowserKit will follow redirections, so to check for 30*
     * HTTP status codes and Location headers, they have to be turned off.
     *
     * @since 1.0.0
     *
     * @param bool $followRedirects Optional. Whether to follow redirects or not.
     *                              Default is true.
     */
    function followRedirects($followRedirects = true)
    {
        $this->getModule('PhpBrowser')->client->followRedirects($followRedirects);
    }

    function grabFragmentParameter($uri, $param_name)
    {
        $params = $this->getQueryParams($uri, '#');
        return $params[$param_name];
    }

    private function getQueryParams($url, $separator = '?')
    {
        $parameters = [];
        if (strpos($url, $separator) !== false) {
            $queryString = explode($separator, $url, 2)[1];
            $explodedQueryString = explode('&', $queryString);
            foreach ($explodedQueryString as $string) {
                $values = explode('=', $string);
                $key = $values[0];
                $val = $values[1];
                $parameters[$key] = $val;
            }
        }
        return $parameters;
    }
}

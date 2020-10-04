<?php

namespace PhpOidc\PhpOp\Api\Response;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\TextResponse;

class NotFound extends Response
{
    public $status_code = 404;

    public function __construct()
    {
        parent::__construct("", $this->status_code);
    }
}

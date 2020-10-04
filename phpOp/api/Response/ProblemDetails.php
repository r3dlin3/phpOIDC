<?php

namespace PhpOidc\PhpOp\Api\Response;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\TextResponse;

class ProblemDetails extends TextResponse
{
    private $status_code = 400;
    private $content_type = 'application/problem+json';

    private $type;
    private $title;
    private $details;


    public function __construct($type, $title = null, $details = null)
    {
        $this->type = $type;
        $this->title = $title;
        $this->details = $details;

        $headers = [
            'Content-Type' => $this->content_type
        ];
        $body = $this->get_body();

        parent::__construct($body, $this->status_code, $headers);
    }

    private function get_body()
    {
        $res = [
            'type' => $this->type,
            'status' => $this->status_code
        ];
        if ($this->title)
            $res['title'] = $this->title;
        if ($this->details)
            $res['details'] = $this->details;

        return json_encode($res);
    }
}

<?php

namespace PhpOidc\PhpOp\Api;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\TextResponse;

class PaginatedResultResponse extends TextResponse
{
    public $status_code = 200;

    private $results;
    private $total;
    private $offset;

    private $content_type = 'application/json; charset=UTF-8';

    public function __construct($results, $total, $offset)
    {
        $this->results = $results;
        $this->total = $total;
        $this->offset = $offset;


        $headers = [
            'content-type' => $this->content_type
        ];
        $body = $this->get_body();

        parent::__construct($body, $this->status_code, $headers);
    }

    public function get_body()
    {
        if (count($this->results) > 0) {

            $from = $this->offset + 1;
            $to = $from + count($this->results) - 1;
        } else {
            $from = $to = 0;
        }
        return json_encode([
            "total_rows" => $this->total,
            "results" => $this->results,
            "from" => $from,
            "to" => $to
        ]);
    }
}

class NotFound extends Response
{
    public $status_code = 404;

    public function __construct()
    {
        parent::__construct("", $this->status_code);
    }
}

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

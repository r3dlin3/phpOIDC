<?php

namespace Controller;

class Response
{
    public $status_code = 200;
    protected $body;

    public $content_type = 'application/json; charset=UTF-8';

    public function __construct($body = null)
    {
        $this->body = $body;
    }

    public function get_body()
    {
        return $this->body;
    }
}

class PaginatedResultResponse extends Response {
    private $results;
    private $total;
    private $offset;

    public function __construct($results, $total, $offset)
    {
        $this->results = $results;
        $this->total = $total;
        $this->offset = $offset;
    }

    public function get_body()
    {
        $from = $this->offset + 1;
        $to = $from + count($this->results);
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
}

class ProblemDetails extends Response
{
    public $status_code = 400;
    public $content_type = 'application/problem+json';

    private $type;
    private $title;
    private $details;


    public function __construct($type, $title = null, $details = null)
    {
        $this->type = $type;
        $this->title = $title;
        $this->details = $details;
    }

    public function get_body()
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

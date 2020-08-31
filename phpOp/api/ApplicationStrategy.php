<?php

declare(strict_types=1);

namespace PhpOidc\PhpOp\Api;

use \Laminas\Diactoros\Response;
use \League\Route\Http\Exception\{MethodNotAllowedException, NotFoundException};
use \League\Route\Route;
use \Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use \Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};
use Throwable;

class ApplicationStrategy extends \League\Route\Strategy\ApplicationStrategy
{


    /**
     * @var ResponseFactoryInterface
     */
    protected $responseFactory;

    /**
     * Construct.
     *
     * @param ResponseFactoryInterface $responseFactory
     * @param int $jsonFlags
     */
    public function __construct(ResponseFactoryInterface $responseFactory)
    {
        $this->responseFactory = $responseFactory;
    }
    /**
     * {@inheritdoc}
     */
    public function getNotFoundDecorator(NotFoundException $exception): MiddlewareInterface
    {
        return $this->returnErrorPage(404);
    }

    /**
     * {@inheritdoc}
     */
    public function getMethodNotAllowedDecorator(MethodNotAllowedException $exception): MiddlewareInterface
    {
        return $this->returnErrorPage(405);
    }

    /**
     * Return a middleware that simply throws an error
     *
     * @param \Throwable $error
     *
     * @return \Psr\Http\Server\MiddlewareInterface
     */
    protected function returnErrorPage(int $status): MiddlewareInterface
    {
        return new class ($status, $this->responseFactory) implements MiddlewareInterface
        {
            protected $status;
            protected $responseFactory;

            public function __construct(int $status, ResponseFactoryInterface $responseFactory)
            {
                $this->responseFactory = $responseFactory;
                $this->status = $status;
            }

            public function process(
                ServerRequestInterface $request,
                RequestHandlerInterface $requestHandler
            ): ResponseInterface {
                $response = $this->responseFactory->createResponse();
                $response = $response->withStatus($this->status);
                return $response;
            }
        };
    }
}

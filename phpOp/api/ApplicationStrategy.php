<?php

declare(strict_types=1);

namespace PhpOidc\PhpOp\Api;

use League\Route\Http\Exception as HttpException;
use League\Route\Http\Exception\{MethodNotAllowedException, NotFoundException};
use League\Route\Route;
use \Psr\Http\Message\{ResponseFactoryInterface, ResponseInterface, ServerRequestInterface};
use \Psr\Http\Server\{MiddlewareInterface, RequestHandlerInterface};
use Respect\Validation\Exceptions\NestedValidationException;
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
        $this->addDefaultResponseHeader('content-type', 'application/json');

    }

    /**
     * Check if the response can be converted to JSON
     *
     * Arrays can always be converted, objects can be converted if they're not a response already
     *
     * @param mixed $response
     *
     * @return bool
     */
    protected function isJsonEncodable($response): bool
    {
        if ($response instanceof ResponseInterface) {
            return false;
        }

        return (is_array($response) || is_object($response));
    }

    /**
     * {@inheritdoc}
     */
    public function invokeRouteCallable(Route $route, ServerRequestInterface $request): ResponseInterface
    {
        $controller = $route->getCallable($this->getContainer());
        $response = $controller($request, $route->getVars());

        if ($this->isJsonEncodable($response)) {
            $body     = json_encode($response);
            $response = $this->responseFactory->createResponse();
            $response->getBody()->write($body);
        }

        $response = $this->applyDefaultResponseHeaders($response);

        return $response;
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

    /**
     * Get a middleware that acts as an exception handler, it should wrap the rest of the
     * middleware stack and catch eny exceptions.
     *
     * @return \Psr\Http\Server\MiddlewareInterface
     */
    public function getExceptionHandler(): MiddlewareInterface
    {
        return new class($this->responseFactory->createResponse()) implements MiddlewareInterface
        {
            protected $response;

            public function __construct(ResponseInterface $response)
            {
                $this->response = $response;
            }

            public function process(
                ServerRequestInterface $request,
                RequestHandlerInterface $requestHandler
            ): ResponseInterface {
                try {
                    return $requestHandler->handle($request);
                } catch (Throwable $exception) {
                    $response = $this->response;

                    if ($exception instanceof NestedValidationException) {
                        return new ProblemDetails(
                            "http://phpoidc.org/validation-error",
                            "Invalid parameters",
                            $exception->getFullMessage()
                        );
                    }

                    if ($exception instanceof HttpException) {
                        return $exception->buildJsonResponse($response);
                    }



                    $response->getBody()->write(json_encode([
                        'status_code'   => 500,
                        'reason_phrase' => $exception->getMessage()
                    ]));

                    $response = $response->withAddedHeader('content-type', 'application/json');
                    return $response->withStatus(500, strtok($exception->getMessage(), "\n"));
                }
            }
        };
    }
}

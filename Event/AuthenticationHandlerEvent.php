<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Represents an authentication handler event, such as success or failure, where the response can be set.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AuthenticationHandlerEvent extends Event
{
    /**
     * The event name that happens after the default authentication success handler is called.
     */
    const SUCCESS = 'ldap_tools_bundle.guard.login.success';

    /**
     * The event name that happens after the default authentication failure handler is called.
     */
    const FAILURE = 'ldap_tools_bundle.guard.login.failure';

    /**
     * The event name that happens when the entry point is called for the guard and returns a redirect/response.
     */
    const START = 'ldap_tools_bundle.guard.login.start';

    /**
     * @var Response
     */
    protected $response;

    /**
     * @var \Exception|null
     */
    protected $exception;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var TokenInterface|null
     */
    protected $token;

    /**
     * @var string|null
     */
    protected $providerKey;

    /**
     * @param Response $response
     * @param Request $request
     * @param \Exception|null $exception
     * @param TokenInterface|null $token
     * @param string|null $providerKey
     */
    public function __construct(Response $response, Request $request, \Exception $exception = null, TokenInterface $token = null, $providerKey = null)
    {
        $this->request = $request;
        $this->response = $response;
        $this->exception = $exception;
        $this->token = $token;
        $this->providerKey = $providerKey;
    }

    /**
     * @return Response
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * @return Request
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * @param Response $response
     * @return $this
     */
    public function setResponse(Response $response)
    {
        $this->response = $response;

        return $this;
    }

    /**
     * @return \Exception|null
     */
    public function getException()
    {
        return $this->exception;
    }

    /**
     * @return null|TokenInterface
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @return null|string
     */
    public function getProviderKey()
    {
        return $this->providerKey;
    }
}

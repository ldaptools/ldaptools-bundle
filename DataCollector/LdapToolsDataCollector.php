<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\DataCollector;

use LdapTools\Bundle\LdapToolsBundle\Log\LdapProfilerLogger;
use LdapTools\LdapManager;
use LdapTools\Log\LogOperation;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

/**
 * Data Collector for LdapTools.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapToolsDataCollector extends DataCollector
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var LdapProfilerLogger
     */
    protected $logger;

    /**
     * LdapToolsDataCollector constructor.
     * @param LdapProfilerLogger $logger
     * @param LdapManager|null $ldap
     */
    public function __construct(LdapProfilerLogger $logger, LdapManager $ldap = null)
    {
        $this->ldap = $ldap;
        $this->logger = $logger;
        $this->reset();
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'ldaptools';
    }

    /**
     * {@inheritdoc}
     */
    public function collect(Request $request, Response $response, \Throwable $exception = null)
    {
        if (!$this->ldap) {
            return;
        }
        $this->data['domains'] = $this->ldap->getDomains();

        $this->data['operations_by_domain'] = [];
        foreach ($this->data['domains'] as $domain) {
            $this->data['operations_by_domain'][$domain] = $this->addOperationToData(...$this->logger->getOperations($domain));
        }
        $this->data['operations'] = $this->addOperationToData(...$this->logger->getOperations());
        $this->data['errors'] = $this->addOperationToData(...$this->logger->getErrors());
    }

    /**
     * {@inheritdoc}
     */
    public function reset()
    {
        $this->data['domains'] = [];
        $this->data['errors'] = [];
        $this->data['operations'] = [];
        $this->data['operations_by_domain'] = [];
    }

    /**
     * @return array
     */
    public function getOperationsByDomain()
    {
        return $this->data['operations_by_domain'];
    }

    /**
     * @return int
     */
    public function getTime()
    {
        $time = 0;

        foreach ($this->data['operations'] as $operation) {
            $time += $operation['duration'];
        }

        return $time;
    }

    /**
     * @return array
     */
    public function getOperations()
    {
        return $this->data['operations'];
    }

    /**
     * @return array
     */
    public function getErrors()
    {
        return $this->data['errors'];
    }

    /**
     * @return string[]
     */
    public function getDomains()
    {
        return $this->data['domains'];
    }

    /**
     * @param \LdapTools\Log\LogOperation[] ...$logs
     * @return array
     */
    protected function addOperationToData(LogOperation ...$logs)
    {
        $logData  = [];

        foreach ($logs as $log) {
            $data = [];

            $data['data'] = $log->getOperation()->getLogArray();
            $data['startTime'] = $log->getStartTime();
            $data['stopTime'] = $log->getStopTime();
            $data['domain'] = $log->getDomain();
            $data['error'] = $log->getError();
            $data['name'] = $log->getOperation()->getName();
            $data['duration'] = ($data['stopTime'] - $data['startTime']) * 1000;

            $logData[] = $data;
        }

        return $logData;
    }
}

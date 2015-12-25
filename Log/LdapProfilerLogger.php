<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Log;

use LdapTools\Log\LdapLoggerInterface;
use LdapTools\Log\LogOperation;

/**
 * Handles LDAP operation logging for use within the profiler.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapProfilerLogger implements LdapLoggerInterface
{
    /**
     * @var LogOperation[]
     */
    protected $opsByDomain = [];

    /**
     * @var LogOperation[]
     */
    protected $allOperations = [];

    /**
     * @var LogOperation[]
     */
    protected $errors = [];

    /**
     * {@inheritdoc}
     */
    public function start(LogOperation $operation)
    {
        if (!isset($this->opsByDomain[$operation->getDomain()])) {
            $this->opsByDomain[$operation->getDomain()] = [];
        }
        $this->opsByDomain[$operation->getDomain()][] = $operation;
        $this->allOperations[] = $operation;
    }

    /**
     * {@inheritdoc}
     */
    public function end(LogOperation $operation)
    {
        if (!is_null($operation->getError())) {
            $this->errors[] = $operation;
        }
    }

    /**
     * Get all of the operations recorded by the profiler. Or get the operations for a specific domain.
     *
     * @param null|string $domain
     * @return LogOperation[]
     */
    public function getOperations($domain = null)
    {
        if (!is_null($domain) && !isset($this->opsByDomain[$domain])) {
            return [];
        } elseif (!is_null($domain)) {
            return $this->opsByDomain[$domain];
        }

        return $this->allOperations;
    }

    /**
     * Get all the operations that had errors.
     *
     * @return LogOperation[]
     */
    public function getErrors()
    {
        return $this->errors;
    }
}

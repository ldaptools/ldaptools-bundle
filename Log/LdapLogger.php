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
use Psr\Log\LoggerInterface;
use Symfony\Component\Stopwatch\Stopwatch;

/**
 * LDAP logger.
 *
 * @author Chad Sikorra <chad.sikorra@gmail.com>
 */
class LdapLogger implements LdapLoggerInterface
{
    /**
     * @var null|LoggerInterface
     */
    protected $logger;

    /**
     * @var null|Stopwatch
     */
    protected $stopwatch;

    /**
     * @param LoggerInterface|null $logger
     * @param Stopwatch|null $stopwatch
     */
    public function __construct(LoggerInterface $logger = null, Stopwatch $stopwatch = null)
    {
        $this->logger = $logger;
        $this->stopwatch = $stopwatch;
    }

    /**
     * {@inheritdoc}
     */
    public function start(LogOperation $log)
    {
        if (!is_null($this->stopwatch)) {
            $this->stopwatch->start('ldaptools', strtolower($log->getOperation()->getName()));
        }
        if (!is_null($this->logger)) {
            $this->log($log);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function end(LogOperation $log)
    {
        if (!is_null($this->stopwatch)) {
            $this->stopwatch->stop('ldaptools');
        }
        if (!is_null($this->logger)) {
            $this->log($log);
        }
    }

    /**
     * Logs a message.
     *
     * @param LogOperation $log
     */
    protected function log(LogOperation $log)
    {
        $message = $this->getLogMessage($log);

        if (!is_null($log->getError())) {
            $this->logger->error($message);
        } else {
            $this->logger->debug($message);
        }
    }

    /**
     * @param LogOperation $log
     * @return string
     */
    protected function getLogMessage(LogOperation $log)
    {
        $startOrStop = is_null($log->getStopTime()) ? 'Start' : 'End';
        $message = "(".$log->getDomain()." on ".$log->getOperation()->getServer().") $startOrStop ".$log->getOperation()->getName()." Operation - ";

        $params = [];
        if (is_null($log->getStopTime())) {
            foreach ($log->getOperation()->getLogArray() as $key => $value) {
                if ($key != "Server") {
                    $params[] = "$key: $value";
                }
            }
        } else {
            if (!is_null($log->getError())) {
                $params[] = "Error: ".$log->getError();
            }
            $params[] = "Completed in ".(round(($log->getStopTime() - $log->getStartTime()) * 1000))." ms.";
        }
        $message .= implode(', ', $params);

        return $message;
    }
}

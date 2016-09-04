<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Log;

use LdapTools\Log\LogOperation;
use LdapTools\Operation\DeleteOperation;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Log\LoggerInterface;
use Symfony\Component\Stopwatch\Stopwatch;

class LdapLoggerSpec extends ObjectBehavior
{
    function let(LoggerInterface $logger, Stopwatch $stopwatch)
    {
        $this->beConstructedWith($logger, $stopwatch);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Log\LdapLogger');
    }

    function it_should_call_the_stopwatch_and_logger_on_start($stopwatch, $logger)
    {
        $log = new LogOperation((new DeleteOperation('foo'))->setServer('foo'));
        $log->setDomain('foo');
        $stopwatch->start('ldaptools', strtolower($log->getOperation()->getName()))->shouldBeCalled();
        $logger->debug(
            "(foo on foo) Start Delete Operation - DN: foo, Controls: array (\n)"
        )->shouldBeCalled();

        $this->start($log);
    }

    function it_should_call_the_stopwatch_and_logger_on_stop($stopwatch, $logger)
    {
        $log = new LogOperation((new DeleteOperation('foo'))->setServer('bar'));
        $log->setDomain('example.local');
        $log->start();
        $log->stop();

        $stopwatch->stop('ldaptools')->shouldBeCalled();
        $logger->debug(
            '(example.local on bar) End Delete Operation - Completed in '.(round(($log->getStopTime() - $log->getStartTime()) * 1000))." ms."
        )->shouldBeCalled();

        $this->end($log);
    }

    function it_should_not_call_the_stopwatch_or_logger_when_they_are_not_used($stopwatch, $logger)
    {
        $log = new LogOperation(new DeleteOperation('foo'));
        $this->beConstructedWith(null, null);

        $logger->debug(Argument::any(), Argument::any())->shouldNotBeCalled();
        $stopwatch->start(Argument::any(), Argument::any())->shouldNotBeCalled();
        $stopwatch->stop(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->start($log->start());
        $this->end($log->stop());
    }

    function it_should_call_the_logger_error_method_when_the_log_contains_an_error($logger)
    {
        $log = new LogOperation((new DeleteOperation('foo'))->setServer('bar'));
        $log->setError('foo');
        $log->setDomain('foo.bar');
        $log->start()->stop();
        $logger->error(
            '(foo.bar on bar) End Delete Operation - Error: foo, Completed in '.(round(($log->getStopTime() - $log->getStartTime()) * 1000))." ms."
        )->shouldBeCalled();

        $this->start($log);
    }
}

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
use LdapTools\Operation\AddOperation;
use LdapTools\Operation\BatchModifyOperation;
use LdapTools\Operation\DeleteOperation;
use PhpSpec\ObjectBehavior;

class LdapProfilerLoggerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Log\LdapProfilerLogger');
    }

    function it_should_implement_the_ldap_logger_interface()
    {
        $this->shouldImplement('\LdapTools\Log\LdapLoggerInterface');
    }

    function it_should_add_the_log_operation_when_calling_start()
    {
        $ops = [
            (new LogOperation(new AddOperation()))->setDomain('foo.bar'),
            (new LogOperation(new DeleteOperation('foo')))->setDomain('foo.bar'),
            (new LogOperation(new BatchModifyOperation('foo')))->setDomain('example.local'),
        ];
        /** @var LogOperation $op */
        foreach ($ops as $op) {
            $this->start($op->start());
        }
        $this->getOperations()->shouldHaveCount(3);

        /** @var LogOperation $op */
        foreach ($ops as $op) {
            $this->end($op->stop());
        }
        $this->getOperations()->shouldHaveCount(3);

        $this->getOperations()->shouldBeEqualTo($ops);
    }

    function it_should_be_able_to_get_operations_by_domain()
    {
        $ops = [
            (new LogOperation(new AddOperation()))->setDomain('foo.bar'),
            (new LogOperation(new BatchModifyOperation('foo')))->setDomain('example.local'),
        ];
        /** @var LogOperation $op */
        foreach ($ops as $op) {
            $this->start($op->start());
        }

        $this->getOperations('foo.bar')->shouldHaveCount(1);
        $this->getOperations('example.local')->shouldHaveCount(1);
    }

    function it_should_be_able_to_get_operations_with_errors()
    {
        $op1 = (new LogOperation(new AddOperation()))->setDomain('foo.bar')->setError('foo');
        $op2 = (new LogOperation(new BatchModifyOperation('foo')))->setDomain('example.local');
        $ops = [
           $op1,
           $op2,
        ];

        /** @var LogOperation $op */
        foreach ($ops as $op) {
            $this->start($op->start());
            $this->end($op->stop());
        }

        $this->getErrors()->shouldBeEqualTo([$op1]);
    }
}

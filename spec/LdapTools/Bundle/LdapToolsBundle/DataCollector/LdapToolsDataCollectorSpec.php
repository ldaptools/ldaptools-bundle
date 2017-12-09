<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\DataCollector;

use LdapTools\Bundle\LdapToolsBundle\Log\LdapProfilerLogger;
use LdapTools\LdapManager;
use LdapTools\Log\LogOperation;
use LdapTools\Operation\AddOperation;
use LdapTools\Operation\DeleteOperation;
use PhpSpec\ObjectBehavior;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class LdapToolsDataCollectorSpec extends ObjectBehavior
{
    function let(LdapManager $ldap)
    {
        $logger = new LdapProfilerLogger();

        // Add some log data...
        $addOperation = (new AddOperation())->setAttributes(['username' => 'foo', 'unicodePwd' => 'bar']);
        $deleteOperation = new DeleteOperation('foo');

        $addLog = new LogOperation($addOperation);
        $addLog->setDomain('foo.bar');
        $addLog->setError('fail');
        $deleteLog = new LogOperation($deleteOperation);
        $deleteLog->setDomain('example.local');

        /** @var LogOperation $log */
        foreach ([$addLog, $deleteLog] as $log) {
            $logger->start($log->start());
            $logger->end($log->stop());
        }

        $ldap->getDomains()->willReturn(['foo.bar', 'example.local']);

        $this->beConstructedWith($logger, $ldap);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\DataCollector\LdapToolsDataCollector');
    }

    function it_should_extend_the_abstract_data_collector()
    {
        $this->shouldBeAnInstanceOf('Symfony\Component\HttpKernel\DataCollector\DataCollector');
    }

    function it_should_get_the_name()
    {
        $this->getName()->shouldBeEqualTo('ldaptools');
    }

    function it_should_collect_data(Request $request, Response $response)
    {
        $this->collect($request, $response);
    }

    function it_should_get_errors(Request $request, Response $response)
    {
        $this->collect($request, $response);
        $this->getErrors()->shouldBeArray();
        $this->getErrors()->shouldHaveCount(1);
        $this->getErrors()->shouldHaveLogKeyAndValue('error', 'fail');
    }

    function it_should_get_all_operations(Request $request, Response $response)
    {
        $this->collect($request, $response);
        $this->getOperations()->shouldBeArray();
        $this->getOperations()->shouldHaveCount(2);
    }

    function it_should_get_operations_by_domain(Request $request, Response $response)
    {
        $this->collect($request, $response);
        $this->getOperationsByDomain()->shouldBeArray();
        $this->getOperationsByDomain()->shouldHaveCount(2);
    }

    function it_should_get_the_domains(Request $request, Response $response)
    {
        $this->collect($request, $response);
        $this->getDomains()->shouldBeEqualTo(['foo.bar','example.local']);
    }

    function it_should_get_the_time_of_all_operations_combined(Request $request, Response $response)
    {
        $this->collect($request, $response);
        $this->getTime()->shouldBeDouble();
        $this->getTime()->shouldNotBeEqualTo(0);
    }

    function it_should_remove_password_information_from_the_operation(Request $request, Response $response)
    {
        $this->collect($request, $response);
        $this->getOperations()->shouldHaveLogKeyAndValue('data', [
            'DN' => null,
            'Attributes' => print_r([
                'username' => 'foo',
                'unicodePwd' => '******',
            ], true),
            'Server' => null,
            "Controls" => "array (\n)",
        ]);
    }

    function it_should_reset_data(Request $request, Response $response)
    {
        $this->collect($request, $response);
        $this->reset();

        $this->getOperations()->shouldBeEqualTo([]);
        $this->getOperationsByDomain()->shouldBeEqualTo([]);
        $this->getDomains()->shouldBeEqualTo([]);
        $this->getTime()->shouldBeEqualTo(0);
        $this->getErrors()->shouldBeEqualTo([]);
    }

    public function getMatchers()
    {
        return [
            'haveLogKeyAndValue' => function($subject, $key, $value) {
                $exists = false;

                foreach ($subject as $log) {
                    if (isset($log[$key]) && $log[$key] == $value) {
                        $exists = true;
                        break;
                    }
                }

                return $exists;
            },
        ];
    }
}

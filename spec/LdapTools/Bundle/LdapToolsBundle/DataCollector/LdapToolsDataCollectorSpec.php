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
use LdapTools\Utilities\LdapUtilities;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapToolsDataCollectorSpec extends ObjectBehavior
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
     * @var LogOperation[]
     */
    protected $logs;

    /**
     * @param \LdapTools\LdapManager $ldap
     */
    function let($ldap)
    {
        $this->ldap = $ldap;
        $this->logger = new LdapProfilerLogger();

        // Add some log data...
        $addOperation = (new AddOperation())->setAttributes(['username' => 'foo', 'unicodePwd' => 'bar']);
        $deleteOperation = (new DeleteOperation())->setDn('foo');

        $addLog = new LogOperation($addOperation);
        $addLog->setDomain('foo.bar');
        $addLog->setError('fail');
        $deleteLog = new LogOperation($deleteOperation);
        $deleteLog->setDomain('example.local');

        $this->logs = [
            $addLog,
            $deleteLog,
        ];

        /** @var LogOperation $log */
        foreach ([$addLog, $deleteLog] as $log) {
            $this->logger->start($log->start());
            $this->logger->end($log->stop());
        }

        $this->ldap->getDomains()->willReturn(['foo.bar', 'example.local']);

        $this->beConstructedWith($this->logger, $this->ldap);
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

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    function it_should_collect_data($request, $response)
    {
        $this->collect($request, $response);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    function it_should_get_errors($request, $response)
    {
        $this->collect($request, $response);
        $this->getErrors()->shouldBeArray();
        $this->getErrors()->shouldHaveCount(1);
        $this->getErrors()->shouldHaveLogKeyAndValue('error', 'fail');
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    function it_should_get_all_operations($request, $response)
    {
        $this->collect($request, $response);
        $this->getOperations()->shouldBeArray();
        $this->getOperations()->shouldHaveCount(2);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    function it_should_get_operations_by_domain($request, $response)
    {
        $this->collect($request, $response);
        $this->getOperationsByDomain()->shouldBeArray();
        $this->getOperationsByDomain()->shouldHaveCount(2);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    function it_should_get_the_domains($request, $response)
    {
        $this->collect($request, $response);
        $this->getDomains()->shouldBeEqualTo(['foo.bar','example.local']);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    function it_should_get_the_time_of_all_operations_combined($request, $response)
    {
        $this->collect($request, $response);
        $this->getTime()->shouldBeDouble();
        $this->getTime()->shouldNotBeEqualTo(0);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    function it_should_remove_password_information_from_the_operation($request, $response)
    {
        $this->collect($request, $response);
        $this->getOperations()->shouldHaveLogKeyAndValue('data', [
            'DN' => null,
            'Attributes' => print_r([
                'username' => 'foo',
                'unicodePwd' => LdapUtilities::MASK,
            ], true),
            'Server' => null,
        ]);
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

<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Form\Type;

use LdapTools\LdapManager;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Query\LdapQuery;
use LdapTools\Query\LdapQueryBuilder;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\OptionsResolver\OptionsResolver;

class LdapObjectTypeSpec extends ObjectBehavior
{
    /**
     * @var OptionsResolver
     */
    protected $resolver;

    public function let(LdapManager $ldap, LdapQueryBuilder $qb, LdapQuery $query, LdapObjectCollection $collection)
    {
        $ldap->getDomainContext()->willReturn('foo.bar');
        $ldap->buildLdapQuery()->willReturn($qb);

        $qb->select(Argument::any())->willReturn($qb);
        $qb->from(Argument::any())->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);
        $query->getResult()->WillReturn($collection);
        $collection->toArray()->willReturn([]);

        $this->resolver = new OptionsResolver();

        if (Kernel::VERSION >= 2.6) {
            $this->resolver->setDefault('ldap_type', 'user');
        } else {
            $this->resolver->setDefaults(['ldap_type' => 'user']);
        }

        $this->beConstructedWith($ldap);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Form\Type\LdapObjectType');
    }

    function it_should_have_a_parent_of_choice()
    {
        $interface = new \ReflectionClass('\Symfony\Component\Form\FormTypeInterface');
        if ($interface->hasMethod('getName')) {
            $expected = 'choice';
        } else {
            $expected = ChoiceType::class;
        }

        $this->getParent()->shouldBeEqualTo($expected);
    }

    function it_should_get_the_name()
    {
        $this->getName()->shouldBeEqualTo('ldap_object');
    }

    function it_should_be_an_instance_of_the_abstract_form_type()
    {
        $this->shouldBeAnInstanceOf('\Symfony\Component\Form\AbstractType');
    }

    function it_should_configure_options_correctly()
    {
        if (Kernel::VERSION >= 2.7) {
            $this->configureOptions($this->resolver);
        } else {
            $this->setDefaultOptions($this->resolver);
        }

        $this->shouldHaveResolverParamWithValue($this->resolver, 'ldap_domain', 'foo.bar');
        $this->shouldHaveResolverParamWithValue($this->resolver, 'ldap_type', 'user');
        $this->shouldHaveResolverParamWithValue($this->resolver, 'choice_name', 'name');
        $this->shouldHaveResolverParamWithValue($this->resolver, 'choice_value', 'guid');
        $this->shouldHaveResolverParamWithValue($this->resolver, 'choices', []);
        $this->shouldNotHaveResolverParam($this->resolver, 'ldap_attributes');

        if (Kernel::VERSION > '2.7') {
            $this->shouldNotHaveResolverParam($this->resolver, 'choice_list');
            $this->shouldHaveResolverParam($this->resolver, 'choice_loader');
        } else {
            $this->shouldHaveResolverParam($this->resolver, 'choice_list');
            $this->shouldNotHaveResolverParam($this->resolver, 'choice_loader');
        }
    }

    public function getMatchers()
    {
        return [
            'haveResolverParamWithValue' => function($subject, OptionsResolver $resolver, $param, $value) {
                $options = $resolver->resolve();

                return isset($options[$param]) && $options[$param] == $value;
            },
            'haveResolverParam' => function($subject, OptionsResolver $resolver, $param) {
                $options = $resolver->resolve();

                return isset($options[$param]);
            },
        ];
    }
}

<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Form\Type;

use LdapTools\Bundle\LdapToolsBundle\Form\ChoiceList\LdapObjectChoiceList;
use LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader\LdapObjectChoiceLoader;
use LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader\LegacyLdapChoiceLoader;
use LdapTools\LdapManager;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\OptionsResolver\OptionsResolverInterface;
use Symfony\Component\OptionsResolver\Options;

/**
 * Provides a form type that represents LDAP object.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapObjectType extends AbstractType
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @param LdapManager $ldap
     */
    public function __construct(LdapManager $ldap)
    {
        $this->ldap = $ldap;
    }

    /**
     * {@inheritdoc}
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $ldap = $this->ldap;

        $resolver->setDefaults([
            'ldap_domain' => $this->ldap->getDomainContext(), // The LDAP domain context
            'ldap_attributes' => null, // The attributes to select
            'ldap_query_builder' => null, // A closure or a LdapQueryBuilder instance
            'choice_name' => 'name',
            'choice_value' => 'guid',
            'choices' => [], // A user supplied array of LDAP objects.
            'choice_loader' => function (Options $options) use ($ldap) {
                if (!interface_exists('\Symfony\Component\Form\ChoiceList\Loader\ChoiceLoaderInterface')) {
                    return null;
                }

                return new LdapObjectChoiceLoader($ldap,
                    $options['ldap_type'],
                    $options['choice_name'],
                    $options['choice_value'],
                    $options['ldap_query_builder']
                );
            },
            'choice_list' => function (Options $options) use ($ldap) {
                // Always prefer the ChoiceLoader if it exists. Fall back to the ObjectChoiceList...
                if (interface_exists('\Symfony\Component\Form\ChoiceList\Loader\ChoiceLoaderInterface')) {
                    return null;
                }
                $legacyChoiceLoader = new LegacyLdapChoiceLoader($ldap, $options['ldap_type'], $options['choice_name'], $options['choice_value'], $options['ldap_query_builder']);
                $preferred = isset($options['preferred_choices']) ? $options['preferred_choices'] : [];

                return new LdapObjectChoiceList(
                    $legacyChoiceLoader->load(),
                    $options['choice_name'],
                    $preferred,
                    null,
                    $options['choice_value']
                );
            },
        ]);
        $resolver->setRequired(['ldap_type']);
        $this->setAllowedTypes($resolver);
    }

    /**
     * {@inheritdoc}
     */
    public function setDefaultOptions(OptionsResolverInterface $resolver)
    {
        $this->configureOptions($resolver);
    }

    /**
     * @return string
     */
    public function getParent()
    {
        // FQCN is needed instead of a simple name in Symfony 3+ ...
        $interface = new \ReflectionClass('\Symfony\Component\Form\FormTypeInterface');

        if ($interface->hasMethod('getName')) {
            $parent = 'choice';
        } else {
            $parent = ChoiceType::class;
        }

        return $parent;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return 'ldap_object';
    }

    /**
     * A rather ugly way of allowing compatibility with the resolver component for pre 2.6 versions.
     *
     * @param OptionsResolver $resolver
     */
    protected function setAllowedTypes(OptionsResolver $resolver)
    {
        $allowed = ['ldap_query_builder', ['\Closure', 'LdapTools\Query\LdapQueryBuilder', 'null']];

        $reflection = new \ReflectionClass(get_class($resolver));
        $parameters = $reflection->getMethod('addAllowedTypes')->getParameters();

        if ($parameters[0]->isArray()) {
            $resolver->setAllowedTypes([$allowed[0] => $allowed[1]]);
        } else {
            $resolver->setAllowedTypes(...$allowed);
        }
    }
}

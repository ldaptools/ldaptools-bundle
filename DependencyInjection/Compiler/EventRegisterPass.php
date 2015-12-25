<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Add any tagged listeners/subscribers to the LdapTools event dispatcher.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class EventRegisterPass implements CompilerPassInterface
{
    /**
     * The event subscriber tag name.
     */
    const SUBSCRIBER_TAG = 'ldap_tools.event_subscriber';

    /**
     * The event listener tag name.
     */
    const LISTENER_TAG = 'ldap_tools.event_listener';

    /**
     * The event dispatcher service name.
     */
    const DISPATCHER = 'ldap_tools.event_dispatcher';

    /**
     * @inheritdoc
     */
    public function process(ContainerBuilder $container)
    {
        $subscribers = $container->findTaggedServiceIds(self::SUBSCRIBER_TAG);
        $listeners = $container->findTaggedServiceIds(self::LISTENER_TAG);

        if (empty($subscribers) && empty($listeners)) {
            return;
        }
        $dispatcher = $container->findDefinition(self::DISPATCHER);

        if (!empty($subscribers)) {
            $this->addSubscribersToEventDispatcher($container, $subscribers, $dispatcher);
        }
        if (!empty($listeners)) {
            $this->addListenersToEventDispatcher($container, $listeners, $dispatcher);
        }
    }

    /**
     * @param ContainerBuilder $container
     * @param array $events
     * @param Definition $dispatcher
     */
    protected function addSubscribersToEventDispatcher(ContainerBuilder $container, array $events, Definition $dispatcher)
    {
        foreach ($events as $id => $event) {
            $this->validateTaggedService($container, $id);
            $dispatcher->addMethodCall('addSubscriber', [new Reference($id)]);
        }
    }

    /**
     * @param ContainerBuilder $container
     * @param array $events
     * @param Definition $dispatcher
     */
    protected function addListenersToEventDispatcher(ContainerBuilder $container, array $events, Definition $dispatcher)
    {
        foreach ($events as $id => $event) {
            $this->validateTaggedService($container, $id);
            if (!isset($event[0]['event'])) {
                throw new \InvalidArgumentException(sprintf('Service "%s" must define the "event" attribute on "%s" tags.', $id, self::LISTENER_TAG));
            }
            if (!isset($event[0]['method'])) {
                throw new \InvalidArgumentException(sprintf('Service "%s" must define the "method" attribute on "%s" tags.', $id, self::LISTENER_TAG));
            }
            $dispatcher->addMethodCall('addListener', [$event[0]['event'], [new Reference($id), $event[0]['method']]]);
        }
    }

    /**
     * @param ContainerBuilder $container
     * @param string $id
     */
    protected function validateTaggedService(ContainerBuilder $container, $id)
    {
        if ($container->getDefinition($id)->isAbstract()) {
            throw new \InvalidArgumentException(sprintf(
                'The abstract service "%s" cannot be tagged as a LdapTools subscriber/listener.',
                $id
            ));
        }
    }
}

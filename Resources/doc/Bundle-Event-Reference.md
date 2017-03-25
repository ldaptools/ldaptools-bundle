Bundle Event Reference
================

These events are specific to the LdapToolsBundle. You can tag a service with `kernel.event_listener` to hook into them:

```yaml
# app/config/services.yml
    app.event.login_listener:
        class: AppBundle\Event\LoadUserListener
        tags:
            - { name: kernel.event_listener, event: ldap_tools_bundle.load_user.before, method: beforeLoadUser }

```

| Event Name  | Event Class Used | Description |
| --------------- | -------------- | ---------- |
| ldap_tools_bundle.load_user.before | `LoadUserEvent` | Triggered before a LDAP user is loaded from the LdapUserProvider. |
| ldap_tools_bundle.load_user.after | `LoadUserEvent` |  Triggered after a LDAP user is loaded from the LdapUserProvider. |
| ldap_tools_bundle.login.success | `LdapLoginEvent` | Triggered directly after a successful LDAP login/bind in the Guard or Auth provider. |
| ldap_tools_bundle.guard.login.start | `AuthenticationHandlerEvent` | Triggered in the Guard when the entry point is called. Can set the response object here. |
| ldap_tools_bundle.guard.login.success | `AuthenticationHandlerEvent` | Triggered in the Guard on successful authentication. Can set the response object here. |
| ldap_tools_bundle.guard.login.failure | `AuthenticationHandlerEvent` | Triggered in the Guard on failed authentication. Can set the response object here.  |

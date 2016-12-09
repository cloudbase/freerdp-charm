# Charm overview

FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. This charm provides Free RDP in order to view the consoles of machines booted inside the OpenStack.

# Charm usage

    juju deploy free-rdp
    juju add-relation free-rdp active-directory
    juju add-relation free-rdp keystone
    juju add-relation free-rdp nova-hyperv

# Charm config

In order to make use of this charm, it must have a relation with `active-directory`, `nova-hyperv`, which is supposed to be inside an Active-Directory domain and with `keystone`. For the moment in `keystone`, config option `preferred-api-version` has to be set to `2` because version `3` is not supported.

This charm is similar to VNC in terms of functionality, so a prerequisite to integrate this into OpenStack is to set the config option `console-access-protocol` to `vnc` for the `nova-cloud-controller` charm in order to install the package `nova-consoleauth`.

Custom URL for FreeRDP dependency can be configured by the operator of the charm. This is addressed towards users that have not yet migrated to Juju 2.0, but need to keep downloads limited to the internal network, or need to validate any binaries that get installed inside their infrastructure. Users that do use Juju 2.0 can leverage juju resources.

    juju config vcredist-url=http://example.com/vcredist.exe
    juju config installer-url=http://example.com/FreeRDPWebConnect.msi

You can browse to `http://ip-address:port` in order to use it separately from OpenStack.

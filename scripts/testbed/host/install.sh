#!/bin/sh
# Runs at image build: installs the units and the first-boot step. Which
# consumers a host runs depends on its name, so it is decided at boot.
set -eu
d=/opt/testbed-host
install -m 0644 $d/units/*.service /etc/systemd/system/
install -m 0755 $d/init.sh /usr/local/sbin/testbed-init.sh
install -m 0755 $d/seen.sh /usr/local/sbin/testbed-seen.sh
systemctl enable testbed-init.service >/dev/null 2>&1 || ln -sf /etc/systemd/system/testbed-init.service /etc/systemd/system/multi-user.target.wants/testbed-init.service

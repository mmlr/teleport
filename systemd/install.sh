#!/bin/sh

cd "$(dirname "$0")"

useradd --system --shell /bin/false teleport

for WHICH in client server
do
	install --owner=root --group=root --target-directory /etc/systemd/system \
		-D teleport-$WHICH.service
	install --owner=teleport --group=teleport --target-directory /etc/teleport \
		-D $WHICH.conf
done

install --owner=teleport --group=teleport --directory /var/teleport

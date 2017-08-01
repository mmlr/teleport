#!/bin/sh

SETTINGS_DIR="$(finddir B_USER_SETTINGS_DIRECTORY)/teleport"
if [ ! -d "$SETTINGS_DIR" -o ! -r "$SETTINGS_DIR/server.conf" ]
then
	exit 0
fi

cd "$SETTINGS_DIR"
source server.conf

if [ "$ENABLED" != "yes" ]
then
	exit 0
fi

teleport server $LISTEN_PORT "$AUTH_DATABASE"

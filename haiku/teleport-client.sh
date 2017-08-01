#!/bin/sh

SETTINGS_DIR="$(finddir B_USER_SETTINGS_DIRECTORY)/teleport"
if [ ! -d "$SETTINGS_DIR" -o ! -r "$SETTINGS_DIR/client.conf" ]
then
	exit 0
fi

cd "$SETTINGS_DIR"
source client.conf

if [ "$ENABLED" != "yes" ]
then
	exit 0
fi

teleport client $CONNECT_HOST $CONNECT_PORT $LOCAL_PORT $REMOTE_PORT \
	"$USERNAME" "$PASSWORD" $LOOP

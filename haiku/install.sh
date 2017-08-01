#!/bin/sh

cd "$(dirname "$0")"

SETTINGS_DIR="$(finddir B_USER_SETTINGS_DIRECTORY)/teleport"

if [ ! -d "$SETTINGS_DIR" ]
then
	mkdir -p "$SETTINGS_DIR"
fi

for WHICH in client server
do
	cp teleport-$WHICH.sh $(finddir B_USER_SETTINGS_DIRECTORY)/boot/launch
	cp $WHICH.conf "$SETTINGS_DIR"
done

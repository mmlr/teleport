#!/bin/sh

cd "$(dirname "$0")"

BINARY=teleport

if [ ! -e "$BINARY" ]
then
	echo "no binary, building"
	./build.sh
fi

BIN_DIR=/usr/local/bin
case $(uname) in
	Haiku)
		BIN_DIR="$(finddir B_USER_NONPACKAGED_BIN_DIRECTORY)"
		echo "installing $BINARY to $BIN_DIR"
		cp "$BINARY" "$BIN_DIR"
	;;

	*)
		BIN_DIR=/usr/local/bin
		echo "installing $BINARY to $BIN_DIR"
		install -o root -g root -t "$BIN_DIR" -D "$BINARY"
	;;
esac

#!/bin/sh

SOURCES="Handshake.cpp ServerSession.cpp Socket.cpp teleport.cpp"
OUTPUT="teleport"
LIBS="-lpthread"
CPPFLAGS="-O3 -Wall -Werror -Wno-multichar -g"

case $(uname) in
	Haiku)
		LIBS="$LIBS -lnetwork"
	;;
esac

GCC_MAJOR_VERSION=$(gcc -v 2>&1 | tail -n1 | sed 's/[^0-9]*\([0-9]\+\).*/\1/')
if [ $GCC_MAJOR_VERSION -gt 2 ]
then
	CPPFLAGS="$CPPFLAGS -Wextra -pedantic -std=c++11"
fi

g++ $SOURCES -o $OUTPUT $CPPFLAGS $LIBS

#!/bin/sh
# Run this to generate all the initial makefiles, etc.

AUTORECONF=`which autoreconf`
if test -z $AUTORECONF; then
    echo "*** No autoreconf found, please install it ***"
    exit 1
fi

aclocal --install -I m4 || exit 1
autoreconf --force --install --verbose || exit 1
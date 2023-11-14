#!/bin/sh

# Simple shell script to check kernel configuration sanity
# for use with MIPL Mobile IPv6 patches
#
# Authors:
# Antti Tuominen          <ajtuomin@tml.hut.fi>
#
# $Id: s.chkconf_kernel.sh 1.4 02/12/20 15:47:23+02:00 antti@jon.mipl.mediapoli.com $
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.

# Default settings for kernel
DFLT_CONFIG_EXPERIMENTAL=y
DFLT_CONFIG_SYSCTL=y
DFLT_CONFIG_PROC_FS=y
DFLT_CONFIG_MODULES=y
DFLT_CONFIG_NET=y
DFLT_CONFIG_NETFILTER=y
DFLT_CONFIG_UNIX=y
DFLT_CONFIG_INET=y
DFLT_CONFIG_IPV6=m
DFLT_CONFIG_IPV6_SUBTREES=y
DFLT_CONFIG_IPV6_IPV6_TUNNEL=m
DFLT_CONFIG_IPV6_MOBILITY=m

TAGS="CONFIG_EXPERIMENTAL CONFIG_SYSCTL CONFIG_PROC_FS CONFIG_MODULES \
      CONFIG_NET CONFIG_NETFILTER CONFIG_UNIX CONFIG_INET CONFIG_IPV6 \
      CONFIG_IPV6_SUBTREES CONFIG_IPV6_IPV6_TUNNEL \
      CONFIG_IPV6_MOBILITY"

LINUX=/usr/src/linux
WARN=0;

echo
echo "Checking kernel configuration...";

for TAG in $TAGS ; do
    VAL=`sed -ne "/^$TAG=/s/$TAG=//gp" $LINUX/.config`;
    eval "DFLT=\$DFLT_$TAG";
    if [ "$VAL" != "$DFLT" ] ; then
	echo " Warning: $TAG should be set to $DFLT";
	let WARN=$WARN+1;
    fi
done

echo
if [ $WARN -eq 0 ] ; then
    echo "All kernel options are as they should.";
    echo "Do 'make oldconfig' for the kernel before compiling.";
else
    echo "Above $WARN options may conflict with MIPL.";
    echo "If you are not sure, use the recommended setting.";
#    echo "Use $0 -fix to do this automatically";
fi
echo

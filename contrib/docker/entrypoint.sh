#!/bin/sh
sysctl net.ipv6.conf.all.disable_ipv6=0 || true
if [ -e /config/ruvchain.conf ]
then
        /ruvchain -useconffile /config/ruvchain.conf
else
        /ruvchain -genconf > /config/ruvchain.conf
        /ruvchain -useconffile /config/ruvchain.conf
fi

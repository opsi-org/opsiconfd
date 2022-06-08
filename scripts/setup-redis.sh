#!/bin/sh
echo "*** Setup redis ***"

sudo sed -i s'/^daemonize yes/daemonize no/' /etc/redis/redis.conf

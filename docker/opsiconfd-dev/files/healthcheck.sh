#!/bin/sh

[ -f /run/.docker-healthy ] && exit 0
exit 1

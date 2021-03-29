# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import redis

print("Clean Redis DB")

redis_client = redis.StrictRedis.from_url("redis://localhost")

keys = redis_client.scan_iter("opsiconfd*")

for key in keys:

	print("Remove key: %s", key)

	redis_client.delete(key)

print("Done")

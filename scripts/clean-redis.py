# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
poetry run python scripts/clean-redis.py
"""

import os

import redis

redis_url = os.environ.get("OPSICONFD_REDIS_INTERNAL_URL") or "redis://localhost"
print(f"Clean Redis DB: {redis_url}")

redis_client = redis.StrictRedis.from_url(redis_url)
keys = redis_client.scan_iter("opsiconfd*", count=1000)
for key in keys:
	print(f"Delete key: {key.decode('utf-8')}")
	redis_client.delete(key)

print("Done")

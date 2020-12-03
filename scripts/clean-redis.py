#!/usr/bin/python3

import redis

print("Clean Redis DB")

redis_client = redis.StrictRedis.from_url("redis://localhost")

keys = redis_client.scan_iter("opsiconfd*")
for key in keys:
	print("Remove key: %s", key)
	redis_client.delete(key)

print("Done")
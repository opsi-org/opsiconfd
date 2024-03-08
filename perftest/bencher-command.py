#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Run command and add results to bencher results
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from subprocess import run
from time import perf_counter


def main() -> None:
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument("-r", "--bencher-results", required=True, help="Write bencher results to FILE")
	arg_parser.add_argument("-b", "--benchmark", default="opsiconfd-perftest", help="Name of the bencher benchmark")
	arg_parser.add_argument("-m", "--measure", required=True, help="Name of the bencher measure")
	arg_parser.add_argument("-i", "--iterations", type=int, default=3, help="Number of iterations")
	arg_parser.add_argument(
		"-x", "--max-avg-seconds", type=float, help="Fail if average execution time exceeds this value (in seconds)", default=0
	)
	arg_parser.add_argument("command", nargs="+", help="Command to run")
	args = arg_parser.parse_args()

	results = []
	for iteration in range(args.iterations):
		print(f"Running command #{iteration + 1}/{args.iterations}", end=": ", flush=True)
		start = perf_counter()
		run(args.command, check=True, capture_output=True, text=True)
		duration = perf_counter() - start
		print(f"{duration:0.3f} seconds", flush=True)
		results.append(duration)

	avg_seconds = sum(results) / len(results)
	min_seconds = min(results)
	max_seconds = max(results)
	print(f"Result: min={min_seconds:0.3f} avg={avg_seconds:0.3f} max={max_seconds:0.3f} seconds", flush=True)

	bencher_results = {}
	if os.path.exists(args.bencher_results):
		with open(args.bencher_results, "r", encoding="utf-8") as file:
			bencher_results = json.loads(file.read())

	if args.benchmark not in bencher_results:
		bencher_results[args.benchmark] = {}
	bencher_results[args.benchmark].update(
		{
			args.measure: {
				"value": avg_seconds * 1000,
				"lower_value": min_seconds * 1000,
				"upper_value": max_seconds * 1000,
			}
		}
	)

	with open(args.bencher_results, "w", encoding="utf-8") as file:
		file.write(json.dumps(bencher_results, indent=2))

	if args.max_avg_seconds > 0 and avg_seconds > args.max_avg_seconds:
		print(
			f"Average execution time of {avg_seconds:0.3f} seconds exceeds maximum of {args.max_avg_seconds:0.3f} seconds", file=sys.stderr
		)
		sys.exit(1)


if __name__ == "__main__":
	main()
	sys.exit(0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
webdav performance test util
"""

import argparse
import os
import shutil
import sys
import tempfile
import time

from OPSI.System import mount, umount  # type: ignore[import]


def main() -> None:
	parser = argparse.ArgumentParser()
	parser.add_argument("--username", default="adminuser", help="Username")
	parser.add_argument("--password", default="adminuser", help="Password")
	parser.add_argument("--base-url", default="https://localhost:4447/depot", help="Base webdav url")
	parser.add_argument("--path", default="/", help="Path to download")
	parser.add_argument("--iterations", type=int, default=1, help="Download iterations")

	args = parser.parse_args()

	if os.geteuid() != 0:
		raise RuntimeError(f"{os.path.basename(sys.argv[0])} requires root privileges")

	print("Start test")

	dst_dir = tempfile.mkdtemp()
	mnt_dir = tempfile.mkdtemp()
	mount(args.base_url, mnt_dir, username=args.username, password=args.password, verify_server_cert=False)
	try:
		start = time.perf_counter()
		for iternum in range(args.iterations):
			shutil.copytree(f"{mnt_dir}/{args.path.lstrip('/')}", os.path.join(dst_dir, str(iternum)))
		elapsed = time.perf_counter() - start

		num_files = 0
		size = 0
		for root, _dirs, files in os.walk(dst_dir):
			for name in files:
				num_files += 1
				size += os.path.getsize(os.path.join(root, name))
		avg_size = 0 if num_files == 0 else size / num_files
		print(f"Fetched {num_files} files with an avgerage size of {avg_size:0.0f} bytes in {elapsed:0.3f} seconds")
	finally:
		shutil.rmtree(dst_dir)
		umount(mnt_dir)
		os.rmdir(mnt_dir)


if __name__ == "__main__":
	main()

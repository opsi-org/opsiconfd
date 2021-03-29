# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import time
import shutil
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--opsiconfd-mount', dest='opsiconfd_mount', action='store', default="", help="Path to WebDav mount")
parser.add_argument('--apache-mount', dest='apache_mount', action='store', default="", help="Path to WebDav mount")
parser.add_argument('--folder', dest='folder', action='store', default="7zip", help="folder to copy")
parser.add_argument('--destination', dest='destination', action='store', default=".", help="destination")

args = parser.parse_args()
print(args)

apache_mount = args.apache_mount
opsiconfd_mount = args.opsiconfd_mount
download_folder = args.folder
destination = args.destination

print("start test")

shutil.rmtree(f'{download_folder}-opsiconfd', ignore_errors=True)

start = time.perf_counter()
shutil.copytree(f"{opsiconfd_mount}/{download_folder}", f"{destination}/{download_folder}-opsiconfd")
end = time.perf_counter()
print("opsiconfd: ", end - start)

shutil.rmtree(f'{download_folder}-apache', ignore_errors=True)
start = time.perf_counter()
shutil.copytree(f"{apache_mount}/{download_folder}", f"{destination}/{download_folder}-apache")
end = time.perf_counter()
print("apache: ", end - start)

print("done")

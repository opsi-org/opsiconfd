# -*- coding: utf-8 -*-

# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.__main__
"""

import os
import sys
import traceback
from multiprocessing import freeze_support

freeze_support()

package_base = os.path.dirname(__file__)
if package_base in sys.path:
	sys.path.remove(package_base)


def main() -> None:
	from opsiconfd.main import main as opsiconfd_main

	try:
		opsiconfd_main()
	except SystemExit as err:
		sys.exit(err.code)
	except KeyboardInterrupt:
		print("Interrupted", file=sys.stderr)
		sys.exit(1)
	except Exception:  # pylint: disable=broad-except
		# Do not let pyinstaller handle exceptions and print:
		# Failed to execute script '__main__'
		traceback.print_exc()
		sys.exit(1)


if __name__ == "__main__":
	main()

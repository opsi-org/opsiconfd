# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.__main__
"""

import sys
import traceback
from multiprocessing import freeze_support

freeze_support()

if __name__ == "__main__":
	from opsiconfd.main import main

	try:
		main()
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

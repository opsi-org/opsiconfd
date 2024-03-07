# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd main.diagnostic
"""

import dataclasses
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from opsicommon.utils import patch_popen
from rich.console import Console

from opsiconfd.check.cli import console_health_check
from opsiconfd.config import config, configure_warnings
from opsiconfd.diagnostic import get_diagnostic_data
from opsiconfd.logging import init_logging, logger
from opsiconfd.utils import compress_data

patch_popen()
configure_warnings()


def health_check_main() -> None:
	init_logging(log_mode="local")
	sys.exit(console_health_check())


def diagnostic_data_main() -> None:
	console = Console(quiet=config.quiet)

	def data_filename() -> str:
		now = datetime.now().strftime("%Y%m%d-%H%M%S")
		return f"opsiconfd-diagnostic-data-{now}.json.lz4"

	try:
		with console.status("Generating diagnostic data", spinner="arrow3"):
			init_logging(log_mode="rich", console=console)

			data_file = Path(config.target if config.target else data_filename())
			if not data_file.is_absolute():
				data_file = Path.cwd() / data_file

			if data_file.exists() and data_file.is_dir():
				data_file = data_file / data_filename()

			class EnhancedJSONEncoder(json.JSONEncoder):
				def default(self, obj: Any) -> Any:
					if dataclasses.is_dataclass(obj):
						return dataclasses.asdict(obj)
					return super().default(obj)

			data = json.dumps(get_diagnostic_data(), cls=EnhancedJSONEncoder, indent=2).encode("utf-8")
			if (suffix := data_file.suffix.strip(".").lower()) in ("lz4", "gz"):
				data = compress_data(data, compression=suffix)

			data_file.write_bytes(data)
			console.print(f"Diagnostic data file '{str(data_file)}' successfully created.")
	except KeyboardInterrupt:
		logger.error("Generation of diagnostic data interrupted")
		console.quiet = False
		console.print("[bold red]Generation of diagnostic data interrupted[/bold red]")
		sys.exit(2)
	except Exception as err:
		logger.error(err, exc_info=True)
		console.quiet = False
		daf = f" '{str(data_file)}'" if data_file else ""
		console.print(f"[bold red]Failed to create diagnostic data file{daf}: {err}[/bold red]")
		sys.exit(1)

	sys.exit(0)

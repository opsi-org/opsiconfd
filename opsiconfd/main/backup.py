# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd backup.main
"""

import asyncio
import base64
import json
import shutil
import sys
import threading
from datetime import datetime
from pathlib import Path

from opsicommon.types import forceHostId
from rich.console import Console
from rich.progress import Progress
from rich.prompt import Prompt

from opsiconfd.application import MaintenanceState, NormalState, app
from opsiconfd.backup import create_backup, read_backup_file_data, restore_backup
from opsiconfd.config import config
from opsiconfd.logging import init_logging, logger
from opsiconfd.redis import delete_locks
from opsiconfd.setup.backend import setup_mysql


def backup_main() -> None:
	if config.delete_locks:
		delete_locks()

	console = Console(quiet=config.quiet)
	backup_file = None

	def backup_filename() -> str:
		now = datetime.now().strftime("%Y%m%d-%H%M%S")
		return f"opsiconfd-backup-{now}.msgpack.lz4{'.aes' if config.password else ''}"

	try:
		if config.password is None:
			# Argument --pasword given without value
			if config.quiet:
				raise RuntimeError("Interactive password prompt not available in quiet mode")
			if not console.file.isatty():
				raise RuntimeError("Interactive password prompt only available with tty")
			config.password = Prompt.ask("Please enter password", console=console, password=True)

		with Progress(console=console, redirect_stdout=False, redirect_stderr=False) as progress:
			init_logging(log_mode="rich", console=progress.console)

			backup_file = Path(config.backup_target if config.backup_target else backup_filename())
			if not backup_file.is_absolute():
				backup_file = Path.cwd() / backup_file

			if backup_file.exists() and backup_file.is_dir():
				backup_file = backup_file / backup_filename()

			if not config.overwrite and backup_file.exists():
				raise FileExistsError(f"Backup file '{str(backup_file)}' already exists, use --overwrite to replace.")

			suffixes = [s.strip(".") for s in backup_file.suffixes[-3:]]

			if suffixes and suffixes[-1] == "aes":
				suffixes.pop()

			compression = None
			if suffixes and suffixes[-1] in ("lz4", "gz"):
				compression = suffixes.pop()
			elif suffixes and suffixes[-1] not in ("msgpack", "json"):
				raise ValueError(f"Invalid compression {suffixes[-1]!r}, valid compressions are 'lz4' and 'gz'")

			encoding = ""
			if suffixes and suffixes[-1] in ("msgpack", "json"):
				encoding = suffixes.pop()
			if encoding not in ("msgpack", "json"):
				raise ValueError(f"Invalid encoding {encoding!r}, valid encodings are 'msgpack' and 'json'")

			maintenance = not config.no_maintenance
			progress.console.print(f"Creating backup [bold]{backup_file.name}[/bold]")
			progress.console.print(
				f"Using arguments: config_files={not config.no_config_files}, redis_data={not config.no_redis_data}, "
				f"maintenance={maintenance}, encoding={encoding}, "
				f"compression={compression or 'none'}, encrypt={bool(config.password)}"
			)
			try:
				if maintenance:
					initalized_event = threading.Event()
					threading.Thread(
						target=asyncio.run,
						args=[
							app.app_state_manager_task(
								manager_mode=True, init_app_state=(MaintenanceState(), NormalState()), initalized_event=initalized_event
							)
						],
						daemon=True,
					).start()
					initalized_event.wait(5)

				create_backup(
					config_files=not config.no_config_files,
					redis_data=not config.no_redis_data,
					backup_file=backup_file,
					file_encoding=encoding,  # type: ignore[arg-type]
					file_compression=compression,  # type: ignore[arg-type]
					password=config.password,
					maintenance=maintenance,
					progress=progress,
				)
			finally:
				app.stop_app_state_manager_task(wait=True)

			progress.console.print(f"Backup file '{str(backup_file)}' successfully created.")
	except KeyboardInterrupt:
		logger.error("Backup interrupted")
		console.quiet = False
		console.print("[bold red]Backup interrupted[/bold red]")
		sys.exit(2)
	except Exception as err:
		logger.error(err, exc_info=True)
		console.quiet = False
		baf = f" '{str(backup_file)}'" if backup_file else ""
		console.print(f"[bold red]Failed to create backup file{baf}: {err}[/bold red]")
		sys.exit(1)
	sys.exit(0)


def get_password_interative(console: Console) -> None:
	if not console.file.isatty():
		raise RuntimeError("Interactive password prompt only available with tty")
	config.password = Prompt.ask("Please enter password", console=console, password=True)


def backup_info_main() -> None:
	console = Console()
	backup_file = None
	try:
		if config.password is None:
			# Argument --pasword given without value
			get_password_interative(console)

		init_logging(log_mode="rich", console=console)
		backup_file = Path(config.backup_file)
		meta_data = read_backup_file_data(backup_file=backup_file, password=config.password).get("meta", {})
		if meta_data.get("type") != "opsiconfd_backup":
			raise ValueError("Not an opsiconfd backup")
		for key, val in meta_data.items():
			if key == "type":
				continue
			console.print(f"[bold]{key}[/bold]: {val}", highlight=False)

	except KeyboardInterrupt:
		logger.error("Backup info interrupted")
		console.quiet = False
		console.print("[bold red]Backup info interrupted[/bold red]")
		sys.exit(2)
	except Exception as err:
		logger.error(err, exc_info=True)
		console.quiet = False
		baf = f" from '{str(backup_file)}'" if backup_file else ""
		console.print(f"[bold red]Failed to get backup info{baf}: {err}[/bold red]")
		sys.exit(1)
	sys.exit(0)


def restore_main() -> None:
	if config.delete_locks:
		delete_locks()

	console = Console(quiet=config.quiet)
	backup_file = None
	try:
		if config.password is None:
			# Argument --pasword given without value
			if config.quiet:
				raise RuntimeError("Interactive password prompt not available in quiet mode")
			get_password_interative(console)

		with Progress(console=console, redirect_stdout=False, redirect_stderr=False) as progress:
			init_logging(log_mode="rich", console=progress.console)
			backup_file = Path(config.backup_file)
			if not backup_file.exists():
				raise FileExistsError(f"Backup file '{str(backup_file)}' not found")

			server_id = config.server_id
			if server_id not in ("backup", "local"):
				server_id = forceHostId(server_id)

			progress.console.print(f"Restoring from [bold]{backup_file.name}[/bold]")
			progress.console.print(
				f"Using arguments: server_id={server_id}, decrypt={bool(config.password)}, "
				f"config_files={config.config_files}, redis_data={config.redis_data}, "
				f"hw_audit={not config.no_hw_audit}, ignore_errors={config.ignore_errors}"
			)

			initalized_event = threading.Event()
			try:
				threading.Thread(
					target=asyncio.run,
					args=[
						app.app_state_manager_task(
							manager_mode=True, init_app_state=(MaintenanceState(), NormalState()), initalized_event=initalized_event
						)
					],
					daemon=True,
				).start()
				initalized_event.wait(5)

				setup_mysql(interactive=True)

				restore_backup(
					backup_file,
					config_files=config.config_files,
					redis_data=config.redis_data,
					hw_audit=not config.no_hw_audit,
					ignore_errors=config.ignore_errors,
					batch=not config.ignore_errors,
					server_id=server_id,
					password=config.password,
					progress=progress,
				)
			finally:
				app.stop_app_state_manager_task(wait=True)

			progress.console.print(f"Backup file '{str(backup_file)}' successfully restored.")
	except KeyboardInterrupt:
		logger.error("Restore interrupted")
		console.quiet = False
		console.print("[bold red]Restore interrupted[/bold red]")
		sys.exit(2)
	except Exception as err:
		logger.error(err, exc_info=True)
		console.quiet = False
		baf = f" from '{str(backup_file)}'" if backup_file else ""
		console.print(f"[bold red]Failed to restore backup{baf}: {err}[/bold red]")
		sys.exit(1)
	sys.exit(0)


def backup_extract_main() -> None:
	console = Console(quiet=config.quiet)
	backup_file = None
	try:
		if config.password is None:
			# Argument --pasword given without value
			if config.quiet:
				raise RuntimeError("Interactive password prompt not available in quiet mode")
			get_password_interative(console)

		with Progress(console=console, redirect_stdout=False, redirect_stderr=False) as progress:
			init_logging(log_mode="rich", console=progress.console)
			backup_file = Path(config.backup_file)
			if not backup_file.exists():
				raise FileExistsError(f"Backup file '{str(backup_file)}' not found")

			extract_dir = Path(config.extract_dir)
			if not extract_dir.is_absolute():
				extract_dir = Path.cwd() / extract_dir

			if extract_dir.exists():
				if not config.overwrite:
					raise FileExistsError(f"Extract directory '{str(extract_dir)}' already exists, use --overwrite to replace.")
				shutil.rmtree(extract_dir)

			progress.console.print(f"Extracting backup [bold]{backup_file.name}[/bold] to [bold]{extract_dir}[/bold]")

			# Read backup data
			data = read_backup_file_data(backup_file=backup_file, progress=progress, password=config.password)
			if data.get("meta", {}).get("type") != "opsiconfd_backup":
				raise ValueError("Not an opsiconfd backup")

			# Create extract directory
			extract_dir.mkdir(parents=True, exist_ok=True)

			# Extract meta data
			restore_task = progress.add_task("Extracting meta data", total=1, refresh_per_second=2)
			meta_file = extract_dir / "meta.json"
			meta_file.write_text(json.dumps(data["meta"], indent=2), encoding="utf-8")
			progress.console.print(f"Extracted meta data to {meta_file}")
			progress.advance(restore_task)

			# Extract database objects
			restore_task = progress.add_task("Extracting database objects", total=len(data["objects"]), refresh_per_second=2)
			objects_dir = extract_dir / "objects"
			objects_dir.mkdir(exist_ok=True)
			for obj_type, objects in data["objects"].items():
				obj_file = objects_dir / f"{obj_type}.json"
				obj_file.write_text(json.dumps(objects, indent=2), encoding="utf-8")
				progress.console.print(f"Extracted {len(objects)} {obj_type} objects to {obj_file}")
				progress.advance(restore_task)

			# Extract config files
			restore_task = progress.add_task("Extracting config files", total=len(data["config_files"]), refresh_per_second=2)
			if data.get("config_files"):
				config_dir = extract_dir / "config_files"
				config_dir.mkdir(exist_ok=True)
				for file_data in data["config_files"].values():
					# Strip leading slash to make path relative
					rel_path = file_data["path"].lstrip("/")
					file_path = config_dir / rel_path
					file_path.parent.mkdir(parents=True, exist_ok=True)
					file_path.write_text(file_data["content"] or "", encoding="utf-8")
					progress.console.print(f"Extracted config file {file_data['path']} to {file_path}")
					progress.advance(restore_task)

			# Extract Redis data
			dumped_keys = data.get("redis", {}).get("dumped_keys")
			if dumped_keys:
				restore_task = progress.add_task("Extracting Redis data", total=len(dumped_keys), refresh_per_second=2)
				redis_dir = extract_dir / "redis"
				redis_dir.mkdir(exist_ok=True)

				# Convert binary data to base64 for JSON serialization
				for idx in range(len(dumped_keys)):
					dumped_keys[idx]["value"] = base64.b64encode(
						dumped_keys[idx]["value"]
						if isinstance(dumped_keys[idx]["value"], bytes)
						else dumped_keys[idx]["value"].encode("utf-8")
					).decode("utf-8")
					progress.advance(restore_task)
				redis_file = redis_dir / "dumped_keys.json"
				redis_file.write_text(json.dumps(dumped_keys, indent=2), encoding="utf-8")
				progress.console.print(f"Extracted Redis data to {redis_file}")

			progress.console.print(f"Backup contents successfully extracted to '{str(extract_dir)}'")

	except KeyboardInterrupt:
		logger.error("Backup extract interrupted")
		console.quiet = False
		console.print("[bold red]Backup extract interrupted[/bold red]")
		sys.exit(2)
	except Exception as err:
		logger.error(err, exc_info=True)
		console.quiet = False
		baf = f" from '{str(backup_file)}'" if backup_file else ""
		console.print(f"[bold red]Failed to extract backup{baf}: {err}[/bold red]")
		sys.exit(1)
	sys.exit(0)

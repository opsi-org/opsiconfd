# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only


class GrafanaPanelConfig:
	def __init__(
		self,
		type: str = "timeseries",
		title: str = "",
		unit: str | None = None,
		decimals: int = 0,
		stack: bool = False,
		yaxis_min: int | str = "auto",
	) -> None:
		self.type = type
		self.title = title
		self.unit = unit or "short"
		self.decimals = decimals
		self.stack = stack
		self.yaxis_min = yaxis_min

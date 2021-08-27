# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
The opsi configuration service.
"""

__version__ = '4.2.0.194'

import contextvars

contextvar_request_id = contextvars.ContextVar("request_id", default=None)
contextvar_client_session = contextvars.ContextVar("client_session", default=None)
contextvar_client_address = contextvars.ContextVar("client_address", default=None)
contextvar_server_timing = contextvars.ContextVar("server_timing", default=None)

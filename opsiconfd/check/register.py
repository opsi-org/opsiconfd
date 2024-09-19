from opsiconfd.check.common import check_manager

__all__ = ["register_checks"]


def register_checks() -> None:
	import opsiconfd.check.backend  # noqa: F401
	import opsiconfd.check.backup  # noqa: F401
	import opsiconfd.check.config  # noqa: F401
	import opsiconfd.check.ssl  # noqa: F401

	print(check_manager.check_ids)

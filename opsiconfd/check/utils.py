def depots() -> list[str]:
	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()
	depots = backend.host_getObjects(type="OpsiDepotserver")
	return [depot.id for depot in depots]

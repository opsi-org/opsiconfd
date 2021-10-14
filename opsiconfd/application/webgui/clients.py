# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui client methods
"""

from typing import Dict, List, Optional

import datetime
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel # pylint: disable=no-name-in-module
from sqlalchemy import select, text, and_, alias, column, delete
from sqlalchemy.dialects.mysql import insert
from sqlalchemy.sql.expression import table
from sqlalchemy.exc import IntegrityError

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from opsiconfd.logging import logger

from .utils import get_mysql, order_by, pagination, get_configserver_id, common_query_parameters, parse_depot_list, parse_client_list, parse_selected_list

mysql = get_mysql()

client_router = APIRouter()


class ClientsResponse(BaseModel): # pylint: disable=too-few-public-methods
	class Result(BaseModel): # pylint: disable=too-few-public-methods
		class Client(BaseModel): # pylint: disable=too-few-public-methods
			clientId: str
			ident: str
			macAddress: str
			description: str
			notes: str
			version_outdated: int
			installationStatus_unknown: int
			installationStatus_installed: int
			actionResult_failed: int
			actionResult_successful: int
		clients: List[Client]
		total: int
	result: Result
	configserver: str


@client_router.get("/api/opsidata/clients", response_model=ClientsResponse)
def clients(commons: dict = Depends(common_query_parameters), #
			selectedDepots: List[str] = Depends(parse_depot_list),
			selected: Optional[List[str]] = Depends(parse_selected_list)
		):  # pylint: disable=too-many-branches, dangerous-default-value, invalid-name
	"""
	Get Clients on selected depots with infos on the client.
	"""
	with mysql.session() as session:
		where = text("h.type = 'OpsiClient'")
		params = {}
		if commons.get("filterQuery"):
			where = and_(
				where,
				text("(h.hostId LIKE :search OR h.description LIKE :search)")
			)
			params["search"] = f"%{commons.get('filterQuery')}%"
		if selectedDepots:
			where = and_(
				where,
				text("""
				COALESCE(
					(
						SELECT TRIM(TRAILING '"]' FROM TRIM(LEADING '["' FROM cs.`values`)) FROM CONFIG_STATE AS cs
						WHERE cs.objectId = h.hostId AND cs.configId = 'clientconfig.depot.id'
					),
					(SELECT cv.value FROM CONFIG_VALUE AS cv WHERE cv.configId = 'clientconfig.depot.id' AND cv.isDefault = 1)
				) IN :depot_ids
				""")
			)
			params["depot_ids"] = selectedDepots

		if selected:
			params["selected"] = selected
		else:
			params["selected"] = [""]

		client_with_depot = alias(
			select(text("""
				h.hostId AS clientId,
				h.hostId AS ident,
				h.hardwareAddress AS macAddress,
				h.description,
				h.notes,
				COALESCE(
					(
						SELECT TRIM(TRAILING '"]' FROM TRIM(LEADING '["' FROM cs.`values`)) FROM CONFIG_STATE AS cs
						WHERE cs.objectId = h.hostId AND cs.configId = 'clientconfig.depot.id'
					),
					(SELECT cv.value FROM CONFIG_VALUE AS cv WHERE cv.configId = 'clientconfig.depot.id' AND cv.isDefault = 1)
				) AS depotId
			""")) \
				.select_from(text("HOST AS h")) \
				.where(where)
			, name="hd"
		)
		query = select(text("""
			hd.clientId,
			hd.ident,
			hd.macAddress,
			hd.description,
			hd.notes,
			(
				SELECT
					COUNT(*)
				FROM
					PRODUCT_ON_DEPOT AS pod
				JOIN
					PRODUCT_ON_CLIENT AS poc ON
						pod.productId = poc.productId AND
						(pod.productVersion != poc.productVersion OR pod.packageVersion != poc.packageVersion)
				WHERE
					poc.clientId = hd.clientId AND
					pod.depotId = hd.depotId
			) AS version_outdated,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.installationStatus = 'unknown'
			) AS installationStatus_unknown,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.installationStatus = 'installed'
			) AS installationStatus_installed,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.actionResult = 'failed'
			) AS actionResult_failed,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.actionResult = 'successful'
			) AS actionResult_successful,
			IF(
				hd.clientId IN :selected,
				TRUE,
				FALSE
			) AS selected
		""")) \
		.select_from(client_with_depot)

		query = order_by(query, commons)
		query = pagination(query, commons)

		result = session.execute(query, params)
		result = result.fetchall()

		total = session.execute(
			select(text("COUNT(*)")).select_from(client_with_depot),
			params
		).fetchone()[0]

		response_data = {
			"result": {
				"clients": [ dict(row) for row in result if row is not None ],
				"total": total
			},
			"configserver": get_configserver_id()
		}
		return JSONResponse(response_data)

class DepotOfClientsResponse(BaseModel): # pylint: disable=too-few-public-methods
	result: Dict[str, str]


@client_router.get("/api/opsidata/clients/depots", response_model=DepotOfClientsResponse)
def depots_of_clients(selectedClients: List[str] = Depends(parse_client_list)): # pylint: disable=too-many-branches, redefined-builtin, dangerous-default-value, invalid-name
	"""
	Get a mapping of clients to depots.
	"""

	#TODO check if clients of config server always work
	params = {}
	if selectedClients != [""] and selectedClients is not None:
		params["clients"] = selectedClients


	with mysql.session() as session:
		where = text("cs.configId='clientconfig.depot.id' AND cs.objectId IN :clients")

		query = select(text("cs.objectId AS client, cs.values"))\
			.select_from(text("CONFIG_STATE AS cs"))\
			.where(where)

		result = session.execute(query, params)
		result = result.fetchall()

		response = {}
		for row in result:
			tmp_dict = dict(row)
			response[tmp_dict.get("client")] = tmp_dict.get("values")[2:-2]
			params["clients"].remove(tmp_dict.get("client"))

		for client in params["clients"]:
			response[client] = get_configserver_id()


		response_data = {
			"result": response
		}
		return JSONResponse(response_data)

class Client(BaseModel): # pylint: disable=too-few-public-methods
	hostId: str
	opsiHostKey: Optional[str]
	description: Optional[str]
	notes: Optional[str]
	hardwareAddress: Optional[str]
	ipAddress: Optional[IPv4Address or IPv6Address]
	inventoryNumber: Optional[str]
	oneTimePassword: Optional[str]
	created: Optional[datetime.datetime]
	lastSeen: Optional[datetime.datetime]

class ClientResponse(BaseModel): # pylint: disable=too-few-public-methods
	status: int
	error: dict
	data: Client

@client_router.post("/api/opsidata/clients")
def create_client(request: Request, client: Client): # pylint: disable=too-many-locals
	"""
	Create OPSI-Client.
	"""

	status_code = 201
	error = None
	data = {}
	headers = None

	values = vars(client)
	values["type"] = "OpsiClient"

	with mysql.session() as session:
		try:
			with mysql.session() as session:
				query = insert(table(
						"HOST",
						column("type"),
						*[column(key) for key in vars(client).keys()] # pylint: disable=consider-iterating-dictionary
					))\
					.values(values)

				session.execute(query)

			headers = {"Location": f"{request.url}/{client.hostId}"}

		except IntegrityError as err:
			logger.error("Could not create client object.")
			logger.error(err)
			error = {"message": str(err), "class": err.__class__.__name__}
			status_code = max(status_code, 409)

		except Exception as err: # pylint: disable=broad-except
			logger.error("Could not create client object.")
			logger.error(err)
			error = {"message": str(err), "class": err.__class__.__name__}
			status_code = max(status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


	return JSONResponse({"status": status_code, "error": error, "data": data}, headers=headers)


@client_router.get("/api/opsidata/clients/{clientid}", response_model=ClientResponse)
def get_client(clientid: str):  # pylint: disable=too-many-branches, dangerous-default-value, invalid-name
	"""
	Get Clients on selected depots with infos on the client.
	"""

	status_code = 200
	error = ""
	data = None

	with mysql.session() as session:

		try:
			query = select(text("""
				h.hostId AS hostId,
				h.type AS type,
				h.description AS description,
				h.notes AS notes,
				h.hardwareAddress AS hardwareAddress,
				h.ipAddress AS ipAddress,
				h.inventoryNumber AS inventoryNumber,
				h.created AS created,
				h.lastSeen AS lastSeen,
				h.opsiHostKey AS opsiHostKey,
				h.oneTimePassword AS oneTimePassword
			"""))\
			.select_from(text("`HOST` AS h"))\
			.where(text(f"h.hostId = '{clientid}' and h.type = 'OpsiClient'")) # pylint: disable=redefined-outer-name

			result = session.execute(query)
			result = result.fetchone()
			if result:
				data = dict(result)
				for key in data.keys():
					if isinstance(data.get(key), (datetime.date, datetime.datetime)):
						data[key] = data.get(key).isoformat()
		except Exception as err: # pylint: disable=broad-except
			logger.error("Could not get client object.")
			logger.error(err)
			error = {"message": str(err), "class": err.__class__.__name__}
			status_code = max(status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

		return JSONResponse({"status": status_code, "error": error, "data": data})

@client_router.delete("/api/opsidata/clients/{clientid}", response_model=ClientResponse)
def delete_client(clientid: str):
	"""
	Delete Client with ID.
	"""

	status_code = 200
	error = ""
	data = None

	with mysql.session() as session:

		try:
			query = select(text("""
				h.hostId AS hostId
			"""))\
			.select_from(text("`HOST` AS h"))\
			.where(text(f"h.hostId = '{clientid}' and h.type = 'OpsiClient'")) # pylint: disable=redefined-outer-name

			result = session.execute(query)
			result = result.fetchone()

			if not result:
				logger.devel("Client does not exist")
				return JSONResponse({"status": status.HTTP_404_NOT_FOUND, "error": {"message": f"Client with id '{clientid}' not found"}, "data": data})

			tables = [
				"OBJECT_TO_GROUP",
				"CONFIG_STATE",
				"PRODUCT_PROPERTY_STATE"
			]

			for table_name in tables:
				query = delete(table(table_name))\
				.where(text(f"objectId = '{clientid}'"))
				session.execute(query)

			tables = [
				"PRODUCT_ON_CLIENT",
				"LICENSE_ON_CLIENT",
				"SOFTWARE_CONFIG"
			]

			for table_name in tables:
				query = delete(table(table_name))\
				.where(text(f"clientId = '{clientid}'"))
				session.execute(query)

			tables = [
				"HARDWARE_CONFIG_1394_CONTROLLER",
				"HARDWARE_CONFIG_AUDIO_CONTROLLER",
				"HARDWARE_CONFIG_BASE_BOARD",
				"HARDWARE_CONFIG_BIOS",
				"HARDWARE_CONFIG_CACHE_MEMORY",
				"HARDWARE_CONFIG_CHASSIS",
				"HARDWARE_CONFIG_COMPUTER_SYSTEM",
				"HARDWARE_CONFIG_DISK_PARTITION",
				"HARDWARE_CONFIG_FLOPPY_CONTROLLER",
				"HARDWARE_CONFIG_FLOPPY_DRIVE",
				"HARDWARE_CONFIG_HARDDISK_DRIVE",
				"HARDWARE_CONFIG_HDAUDIO_DEVICE",
				"HARDWARE_CONFIG_IDE_CONTROLLER",
				"HARDWARE_CONFIG_KEYBOARD",
				"HARDWARE_CONFIG_MEMORY_BANK",
				"HARDWARE_CONFIG_MEMORY_MODULE",
				"HARDWARE_CONFIG_MONITOR",
				"HARDWARE_CONFIG_NETWORK_CONTROLLER",
				"HARDWARE_CONFIG_OPTICAL_DRIVE",
				"HARDWARE_CONFIG_PCI_DEVICE",
				"HARDWARE_CONFIG_PCMCIA_CONTROLLER",
				"HARDWARE_CONFIG_POINTING_DEVICE",
				"HARDWARE_CONFIG_PORT_CONNECTOR",
				"HARDWARE_CONFIG_PRINTER",
				"HARDWARE_CONFIG_PROCESSOR",
				"HARDWARE_CONFIG_SCSI_CONTROLLER",
				"HARDWARE_CONFIG_SYSTEM_SLOT",
				"HARDWARE_CONFIG_TAPE_DRIVE",
				"HARDWARE_CONFIG_TPM",
				"HARDWARE_CONFIG_USB_CONTROLLER",
				"HARDWARE_CONFIG_USB_DEVICE",
				"HARDWARE_CONFIG_VIDEO_CONTROLLER"
			]

			for table_name in tables:
				query = delete(table(table_name))\
				.where(text(f"hostId = '{clientid}'"))
				session.execute(query)

			query = delete(table("HOST"))\
			.where(text(f"HOST.hostId = '{clientid}' and HOST.type = 'OpsiClient'"))
			session.execute(query)

		except Exception as err: # pylint: disable=broad-except
			logger.error("Could not delete client object.")
			logger.error(err)
			error = {"message": str(err), "class": err.__class__.__name__}
			status_code = max(status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

		return JSONResponse({"status": status_code, "error": error, "data": data})

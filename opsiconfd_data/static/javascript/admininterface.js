function createUUID() {
	if (typeof crypto.randomUUID === "function") {
		return crypto.randomUUID();
	}
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
		var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
		return v.toString(16);
	});
}


function showNotifcation(message, group = "", type = "success", seconds = 10) {
	// type: success / warning / error
	const notifications = document.getElementById("notifications");
	const notifcation = document.createElement("div");
	if (group) {
		const el = document.getElementById(`notification-${group}`);
		if (el) {
			notifications.removeChild(el);
		}
		notifcation.setAttribute("id", `notification-${group}`);
	}
	notifcation.classList.add(type);

	const close = document.createElement("span");
	close.classList.add("close-notification");
	close.onclick = function () {
		try {
			notifications.removeChild(notifcation);
		} catch { }
	}
	notifcation.appendChild(close);

	const msg = document.createElement("p");
	msg.innerHTML = message;
	notifcation.appendChild(msg);

	notifications.appendChild(notifcation);
	if (seconds > 0) {
		setTimeout(function () {
			try { notifications.removeChild(notifcation); } catch { }
		}, seconds * 1000);
	}
}


function monitorSession() {
	if ((document.cookie && document.cookie.indexOf('opsiconfd-session=') != -1) || messagebusWS) {
		setTimeout(monitorSession, 1000);
	}
	else {
		console.info('Session expired')
		location.href = "/login";
	}
}


function getAppState() {
	let req = ajaxRequest("GET", "/admin/app-state");
	req.then((result) => {
		outputToHTML(result, "application-state");
		return result
	});
}


function setAppState(type, button) {
	if (button) {
		button.classList.add("loading");
	}
	params = { "type": type }
	if (type == "maintenance") {
		params.auto_add_to_address_exceptions = true;
		let val = document.getElementById("application-state-maintenance-exceptions").value;
		if (val) {
			params.address_exceptions = val.replace(/\s/g, "").split(",");
		}
		val = document.getElementById("application-state-maintenance-retry-after").value;
		if (val) {
			params.retry_after = val;
		}
	}
	let req = ajaxRequest("POST", "/admin/app-state", params);
	req.then((result) => {
		if (button) {
			button.classList.remove("loading");
		}
		console.debug(result);
		outputToHTML(result, "application-state");
		return result
	}, (error) => {
		if (button) {
			button.classList.remove("loading");
		}
		console.error(error);
		showNotifcation(`Error setting application state: ${error.message}`, "app-state", "error", 10);
	});
}


function createBackup() {
	const button = document.getElementById("create-backup-create-button");
	button.classList.add("loading");
	const config_files = document.getElementById("create-backup-config-files").checked;
	const maintenance_mode = document.getElementById("create-backup-maintenance-mode").checked;
	const password = document.getElementById("create-backup-password").value;
	const req = rpcRequest("service_createBackup", [config_files, maintenance_mode, password, "file_id"]);
	req.then((response) => {
		console.debug(response);
		if (response.error) {
			showNotifcation(`Failed to create backup: ${response.error.message}`, "backup", "error", 30);
		}
		else {
			showNotifcation("Backup successfully created", "backup", "success", 5);
			const link = document.createElement('a');
			link.setAttribute('href', `/file-transfer/${response.result}`);
			link.style.display = 'none';
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);
		}
		button.classList.remove("loading");
	}, (error) => {
		console.error(error);
		showNotifcation(`Failed to create backup: ${error.message || JSON.stringify(error)}`, "backup", "error", 30);
		button.classList.remove("loading");
	});
}


function restoreBackup() {
	const file = document.getElementById("restore-backup-file").files[0];
	if (!file) {
		showNotifcation("Backup file not provided", "restore", "error", 3);
		return;
	}

	const serverIDSelect = document.querySelector('input[name="restore-backup-server-id-select"]:checked').value;
	let serverID = document.getElementById("restore-backup-server-id").value;
	if (serverIDSelect == "backup" || serverIDSelect == "local") {
		serverID = serverIDSelect;
	}
	if (!serverID) {
		showNotifcation("Server ID not provided", "restore", "error", 3);
		return;
	}
	const password = document.getElementById("restore-backup-password").value;
	const button = document.getElementById("restore-backup-create-button");
	button.classList.add("loading");

	const formData = new FormData();
	formData.append("file", file);

	const req = ajaxRequest("POST", "/file-transfer/multipart", formData);
	req.then((response) => {
		console.debug(response);
		const configFiles = document.getElementById("restore-backup-config-files").checked;
		const batch = true;
		const req = rpcRequest(
			"service_restoreBackup", [response.file_id, configFiles, serverID, password, batch]
		);
		req.then((response) => {
			console.debug(response);
			if (response.error) {
				showNotifcation(`Failed to restore backup: ${response.error.message}`, "restore", "error", 30);
			}
			else {
				showNotifcation("Backup successfully restored", "restore", "success", 5);
			}
			button.classList.remove("loading");
		});
	}, (error) => {
		console.error(error);
		showNotifcation(`Failed to restore backup: ${error.message || JSON.stringify(error)}`, "restore", "error", 30);
		button.classList.remove("loading");
	});
}


function unblockAll() {
	let req = ajaxRequest("POST", "/admin/unblock-all");
	req.then((result) => {
		outputToHTML(result, "json-result");
		outputResult(result, "text-result");
		loadClientTable()
		return result
	});
}


function unblockClient(ip) {
	if (ValidateIPaddress(ip)) {
		let req = ajaxRequest("POST", "/admin/unblock-client", { "client_addr": ip });
		req.then((result) => {
			outputToHTML(result, "json-result");
			outputResult(result, "text-result");
			loadClientTable()
			return result
		});
	}
}


function loadRPCCacheInfo() {
	let req = ajaxRequest("GET", "/redis-interface/load-rpc-cache-info");
	req.then((result) => {
		printRPCCacheInfoTable(result.result, "rpc-cache-info-div");
	});
}


function clearRPCCache(cacheName = null) {
	let req = ajaxRequest("POST", "/redis-interface/clear-rpc-cache", { "cache_name": cacheName });
	req.then((result) => {
		loadRPCCacheInfo();
	});
}


function loadClientTable() {
	let req = ajaxRequest("GET", "/admin/blocked-clients");
	req.then((result) => {
		printClientTable(result, "blocked-clients-div");
		return result
	});
}


function loadLockedProductsTable() {
	let req = ajaxRequest("GET", "/admin/locked-products-list");
	req.then((result) => {
		printLockedProductsTable(result, "locked-products-table-div");
		return result
	});
}


function unlockProduct(product) {
	let req = ajaxRequest("POST", "/admin/products/" + product + "/unlock");
	req.then((result) => {
		loadLockedProductsTable();
		return result
	});
}


function unlockAllProducts() {
	let req = ajaxRequest("POST", "/admin/products/unlock");
	req.then((result) => {
		loadLockedProductsTable();
		return result
	});
}


function loadRedisInfo() {
	let req = ajaxRequest("GET", "/redis-interface/redis-stats");
	req.then((result) => {
		outputToHTML(result, "redis-result");
		return result
	});
}


function loadSessionTable() {
	let req = ajaxRequest("GET", "/admin/session-list");
	req.then((result) => {
		printSessionTable(result, "session-table-div");
		return result
	});
}

function loadRPCTable(sortKey, sort) {
	let req = ajaxRequest("GET", "/admin/rpc-list");
	req.then((result) => {
		if (result.length == 0) {
			document.getElementById("rpc-table-div").innerHTML = "No rpcs found.";
			return null
		}
		if (sort) {
			result = sortRPCTable(result, sortKey);
		}
		printRPCTable(result, "rpc-table-div");
		return result;
	});
}

function clearMFAQRCode() {
	document.getElementById('mfa-instructions').innerHTML = "";
}


function updateMultiFactorAuth(userId, type) {
	clearMFAQRCode();
	let req = ajaxRequest("POST", "/admin/update-multi-factor-auth", { "user_id": userId, "type": type });
	req.then((result) => {
		if (result) {
			let html = `<pre id="mfa-instructions" style="line-height: 1.0;">${result}</pre>`;
			html += "<p>Your multi-factor secret has been changed.<br>";
			html += "Please use an app like Google Authenticator and scan the QR code displayed.<br>"
			html += "The app will then generate a new one-time password every 30 seconds.<br>"
			html += "Without this password you will not be able to log in to the opsi server anymore.</p>"
			html += '<button onClick="clearMFAQRCode();">All done, hide instructions and QR code.</button>';
			document.getElementById("mfa-instructions").innerHTML = html;
		}
		loadUserTable();
	});
}


function printUserTable(data, htmlId) {
	if (data.length == 0) {
		htmlStr = "<p>No users found.</p>";
	} else {
		data.sort((a, b) => (a.id > b.id) ? 1 : -1);
		htmlStr = "<table class=\"user-table\" id=\"user-table\">" +
			"<tr>" +
			"<th class='user-th'>User-ID</th>" +
			"<th class='user-th'>Last login</th>" +
			"<th class='user-th'>Messagebus</th>";
		if (multiFactorAuth == "totp_optional" || multiFactorAuth == "totp_mandatory") {
			htmlStr += "<th class='user-th'>MFA state</th>";
			htmlStr += "<th class='user-th'>Activate Time-based one-time password</th>";
			if (multiFactorAuth == "totp_optional") {
				htmlStr += "<th class='user-th'>Deactivate Multi-factor auth</th>";
			}
		}
		htmlStr += "</tr>";
		data.forEach(user => {
			let cls = "user-" + (user.connectedToMessagebus ? "connected" : "not-connected");
			htmlStr += "<tr>" +
				`<td class="user-td">${user.id}</td>` +
				`<td class="user-td">${formateDate(new Date(user.lastLogin))}</td>` +
				`<td id="user-messagebus-state-${user.id}" data-user-id="${user.id}" class="user-td ${cls}">` +
				`${user.connectedToMessagebus ? 'connected' : 'not connected'}</td >`;
			if (multiFactorAuth == "totp_optional" || multiFactorAuth == "totp_mandatory") {
				cls = "mfa-" + (user.mfaState == "inactive" ? "inactive" : "active");
				if (multiFactorAuth == "totp_mandatory" && user.mfaState == "inactive") {
					cls += "-warn";
				}
				htmlStr += `<td class="user-td ${cls}">${user.mfaState}</td>`;
				htmlStr += `<td class="user-td"><input type="button" onclick="updateMultiFactorAuth('${user.id}', 'totp')" value="Generate new secret and activate TOTP"</td>`;
				if (multiFactorAuth == "totp_optional") {
					htmlStr += `<td class="user-td"><input type="button" onclick="updateMultiFactorAuth('${user.id}', 'inactive')" value="Deactivate MFA"</td>`;
				}
			}
		});
		htmlStr += "</table>";
	}
	div = document.getElementById(htmlId);
	div.innerHTML = htmlStr;
	return htmlStr;
}

function loadUserTable() {
	let req = ajaxRequest("GET", "/admin/user-list");
	req.then((result) => {
		printUserTable(result, "user-table-div");
		return result
	});
}

function loadAddons() {
	let req = ajaxRequest("GET", "/admin/addons");
	req.then((result) => {
		printAddonTable(result, "addon-table-div");
		return result
	});
}


function installAddon() {
	const file = document.getElementById("addon-file").files[0];
	if (!file) {
		showNotifcation(`Addon file not provided`, "addon", "error", 3);
		return;
	}

	let button = null;
	if (window.event.currentTarget && window.event.currentTarget.tagName.toLowerCase() == "button") {
		button = window.event.currentTarget;
		button.classList.add("loading");
	}

	let formData = new FormData();
	formData.append("addonfile", file);

	let req = ajaxRequest("POST", "/admin/addons/install", formData);
	req.then((result) => {
		if (button) {
			button.classList.remove("loading");
		}
		loadAddons();
		showNotifcation("Addon successfully installed", "addon", "success", 3);
	}, (error) => {
		if (button) {
			button.classList.remove("loading");
		}
		console.log(error);
		console.warn(error.status, error.details);
		showNotifcation(`Failed to install addon: ${error.message || JSON.stringify(error)}`, "addon", "error", 30);
	});
}

function deleteClientSessions() {
	body = {
		"client_addr": sessionAddr.value
	};
	if (ValidateIPaddress(sessionAddr.value)) {
		let req = ajaxRequest("POST", "/admin/delete-client-sessions", body);
		req.then((result) => {
			outputToHTML(result, "json-result");
			outputResult(result, "text-result");
			return result

		}, (error) => {
			console.log(error);
		});
	}
}


function loadInfo() {
	let config_req = ajaxRequest("GET", "/admin/config");
	config_req.then((result) => {
		outputToHTML(result, "config-values");
		return result;
	});
	let routes_req = ajaxRequest("GET", "/admin/routes");
	routes_req.then((result) => {
		outputToHTML(result, "route-values");
		return result;
	});
}


function reload() {
	let req = ajaxRequest("POST", "/admin/reload");
	req.then((result) => {
		console.debug(result);
		return result
	});
}

function callRedis() {
	let req = ajaxRequest("POST", "/redis-interface", { "cmd": document.getElementById("redis-cmd").value });
	req.then((result) => {
		console.debug(`Redis command successful: ${JSON.stringify(result)}`)
		outputToHTML(result, "redis-result");
	}, (error) => {
		console.error(error);
		outputToHTML(error, "redis-result");
	});
}


function fillRPCMethodSelect() {
	const addDeprecated = document.getElementById("jsonrpc-deprecated-methods").checked;
	const select = document.getElementById("jsonrpc-method-select");
	select.innerHTML = "";
	JSONRPCInterface.forEach(method => {
		if (!method.deprecated || addDeprecated) {
			const option = document.createElement("option");
			option.text = method.name;
			select.appendChild(option);
		}
	});
	onRPCInterfaceMethodSelected();
}

function onRPCInterfaceMethodSelected() {
	let value = document.getElementById("jsonrpc-method-select").value;
	let table = document.getElementById("jsonrpc-request-table");
	var elements = table.getElementsByClassName("param");
	while (elements.length > 0) {
		table.removeChild(elements[0]);
	}
	JSONRPCInterface.forEach(method => {
		if (method.name == value) {
			method.params.forEach(param => {
				let tr = document.createElement("tr");
				tr.className = "param";
				tr.innerHTML = "\
							<td align=\"left\"><label>" + param + ": </label></td> \
							<td><input class=\"jsonrpc-param-input\" type=\"text\" id=\"" + param + "\" name=\"" + param + "\" oninput=\"changeRequestJSON(this.name,this.value)\" /></td> \
						";
				table.appendChild(tr);
			});
			let doc = "";
			if (method.deprecated) {
				doc += '<span class="jsonrpc-deprecated-method">This method is deprecated and will be removed in one of the next versions.</span><br />';
				if (method.alternative_method) {
					doc += `Please use the method '<strong>${method.alternative_method}</strong>' instead.<br />`
				}
			}
			if (method.doc) {
				doc += method.doc;
			}
			document.getElementById("jsonrpc-method-doc").innerHTML = doc;
		}
	});
	changeRequestJSON();
}


function createRequestJSON() {
	let apiJSON = {
		"id": 1,
		"jsonrpc": "2.0",
		"method": "",
		"params": []
	}

	let option = document.getElementById("jsonrpc-method-select");
	let method = option.options[option.selectedIndex].text;
	let inputs = document.getElementsByClassName("jsonrpc-param-input");
	let parameter = [];

	apiJSON.method = method;

	document.getElementById("jsonrpc-request-error").innerHTML = "";
	for (i = 0; i < inputs.length; i++) {
		let name = null;
		let value = null;
		try {
			name = inputs[i].name.trim();
			value = inputs[i].value.trim();
			if (value) {
				parameter.push(JSON.parse(value));
			} else if (!name.startsWith("*")) {
				parameter.push(null);
			}
		} catch (e) {
			console.warn(`${name}: ${e}`);
			document.getElementById("jsonrpc-request-error").innerHTML = `${name}: ${e}`;
		}
	}

	apiJSON.params = parameter;
	return apiJSON;
}


function changeRequestJSON(name, value) {
	let apiJSON = createRequestJSON();
	outputToHTML(apiJSON, "jsonrpc-request");
}


function callJSONRPC() {
	let inputs = document.getElementById("tab-rpc-interface").getElementsByTagName("input");
	for (i = 0; i < inputs.length; i++) {
		let name = inputs[i].name.trim();
		let value = inputs[i].value.trim();

		if (!value && name.substring(0, 1) != "*") {
			const error = `Mandatory field '${inputs[i].name}' is empty`;
			showNotifcation(error, "jsonrpc", "error", 3);
			return {
				"error": error
			};
		}
	}

	let apiJSON = createRequestJSON();
	let req = ajaxRequest("POST", "/rpc", apiJSON, true, true);
	document.getElementById("jsonrpc-execute-button").disabled = true;
	req.then((result) => {
		let serverTimings = {};
		result.requestInfo.serverTiming.split(",").forEach(function (item) {
			let tmp = item.split(";");
			serverTimings[tmp[0]] = parseFloat(tmp[1].split("=")[1]);
		})
		document.getElementById("jsonrpc-response-info").innerHTML = `Request processing: ${serverTimings.request_processing} ms`;
		outputToHTML(result.data, "jsonrpc-result");
		return result;
	}).finally(() => {
		document.getElementById("jsonrpc-execute-button").disabled = false;
	});
}


function loadLicensingInfo() {
	let req = ajaxRequest("GET", "/admin/licensing_info");
	req.then(() => {
		if (typeof result.module_dates != "undefined" && Object.keys(result.module_dates).length > 0) {
			generateLiceningInfoTable(result.info, "licensing-info");
			generateLiceningDatesTable(result.module_dates, result.active_date, "licensing-dates");
		} else {
			div = document.getElementById("licensing-info").innerHTML = "<p>No licenses available.</p>";
			div = document.getElementById("licensing-dates").innerHTML = "";
		}
	});
}


function licenseUpload(files) {
	var formData = new FormData();
	for (var i = 0; i < files.length; i++) {
		formData.append("files", files[i]);
	}
	let req = ajaxRequest("POST", "/admin/license_upload", formData);
	req.then((result) => {
		console.log(`File upload successful: ${JSON.stringify(result)}`)
		loadLicensingInfo();
	});
}


function outputResult(json, id) {
	if (json == undefined) {
		return
	}
	let text = "";
	if (json["status"] == 200) {
		data = json["data"]
		let failedCount = 0;
		let blockedCount = 0;
		if (data["redis-keys"] != undefined) {
			data["redis-keys"].forEach(element => {
				// console.log(element);
				if (element.includes("failed_auth")) {
					failedCount += 1;
				}
				else {
					blockedCount += 1;
				}
			});
		}
		if (data["clients"] != undefined && data["clients"].length != 0) {
			if (blockedCount == 0) {
				text = "No blocked clients found."
			}
			else if (blockedCount == 1) {
				text = blockedCount + " client unblocked.";
			} else {
				text = blockedCount + " clients unblocked.";
			}
			if (failedCount == 1) {
				text = text + " Failed logins for " + failedCount + " client deleted.";
			} else {
				text = text + " Failed logins for " + failedCount + " clients deleted.";
			}

		} else if (data["sessions"] != undefined) {
			if (data["sessions"] != 0) {
				text = "All sessions from client " + data["client"] + " deleted.";
			} else {
				text = "No sessions on client found.";
			}
		} else if (data["client"] != undefined && data["client"].length != 0) {
			text = "Client with address " + data["client"] + " unblocked.";
		} else {
			text = "No blocked clients found.";
		}
	} else {
		text = "Error while unblocking clients.";
	}
	document.getElementById(id).style.visibility = 'visible';
	document.getElementById(id).innerHTML = text;
}


// https://stackoverflow.com/questions/4810841/pretty-print-json-using-javascript
function syntaxHighlight(json) {
	if (typeof json != 'string') {
		json = JSON.stringify(json, undefined, 2);
	}
	json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
	return json.replace(
		/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
		function (match) {
			var cls = 'json_number';
			if (/^"/.test(match)) {
				if (/:$/.test(match)) {
					cls = 'json_key';
				} else {
					cls = 'json_string';
				}
			} else if (/true|false/.test(match)) {
				cls = 'json_boolean';
			} else if (/null/.test(match)) {
				cls = 'json_null';
			}
			return '<span class="' + cls + '">' + match + '</span>';
		});
}

function ValidateIPaddress(ipaddress) {
	if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
		.test(ipaddress)) {
		return (true)
	}
	showNotifcation("You have entered an invalid IP address.", "", "error", 3);
	return (false)
}


function printSessionTable(data, htmlId) {
	if (data.length == 0) {
		htmlStr = "<p>No sessions found.</p>";
	} else {
		data.sort((a, b) => (a.session_id > b.session_id) ? 1 : -1);
		htmlStr = "<table class=\"session-table\" id=\"session-table\">" +
			"<tr>" +
			"<th class='session-th'>Address</th>" +
			"<th class='session-th'>Session ID</th>" +
			"<th class='session-th'>User-Agent</th>" +
			"<th class='session-th'>Username</th>" +
			"<th class='session-th'>Validity</th>" +
			"</tr>";
		data.forEach(element => {
			htmlStr += "<tr>" +
				"<td class=\"session-td\">" + element.address + "</td>" +
				"<td class=\"session-td\">" + element.session_id + "</td>" +
				"<td class=\"session-td\">" + element.user_agent + "</td>" +
				"<td class=\"session-td\">" + element.username + "</td>" +
				"<td class=\"session-td\">" + Math.round(element.validity) + "</td>" +
				"</tr>";
		});
		htmlStr += "</table>";
	}
	div = document.getElementById(htmlId);
	div.innerHTML = htmlStr;
	return htmlStr;
}


function printLockedProductsTable(data, htmlId) {
	if (data == undefined) {
		htmlStr = "<p>No locked Products found.</p>";
	}
	else if (Object.keys(data).length === 0) {
		htmlStr = "<p>No locked Products found.</p>";
	} else {
		htmlStr = "<table class=\"locked-products-table\" id=\"session-table\">" +
			"<tr>" +
			"<th class='locked-products-th'>Product</th>" +
			"<th class='locked-products-th'>Depots</th>"
		"</tr>";
		for (var key in data) {
			htmlStr += "<tr>" +
				"<td class=\"locked-products-td\" class=\"cell-breakWord \">" + key + "</td>" +
				"<td class=\"locked-products-td\">"
			data[key].forEach(element => {
				htmlStr += element + "<br>"
			});
			htmlStr += "</td>"
			htmlStr += "<td class=\"locked-products-td\"><input type=\"button\" onclick=\"unlockProduct('" + key + "')\" value=\"Unlock\"</td>"
			htmlStr += "</tr>";
		}
		htmlStr += "</table>";
	}
	div = document.getElementById(htmlId);
	div.innerHTML = htmlStr;
	return htmlStr;
}


function printAddonTable(data, htmlId) {
	if (data == undefined) {
		htmlStr = "<p>No addons loaded.</p>";
	}
	else if (data.length == 0) {
		htmlStr = "<p>No addons loaded.</p>";
	} else {
		htmlStr = "<table class=\"addon-table\" id=\"addon-table\">" +
			"<tr>" +
			"<th class='addon-th'>Addon ID</th>" +
			"<th class='addon-th'>Name</th>" +
			"<th class='addon-th'>Version</th>" +
			"<th class='addon-th'>Install path</th>" +
			"</tr>";
		data.forEach(element => {
			htmlStr += "<tr>" +
				"<td class=\"addon-td\"><a href=\"" + element.path + "\" target=\"_blank\">" + element.id + "</a></td>" +
				"<td class=\"addon-td\">" + element.name + "</td>" +
				"<td class=\"addon-td\">" + element.version + "</td>" +
				"<td class=\"addon-td\">" + element.install_path + "</td>" +
				"</tr>";
		});
		htmlStr += "</table>";
	}
	div = document.getElementById(htmlId);
	div.innerHTML = htmlStr;
	return htmlStr;
}


function printClientTable(data, htmlId) {
	if (data == undefined) {
		data = []
	}
	if (data.length == 0) {
		htmlStr = "<p>No clients are blocked by the server.</p>";
	} else {
		htmlStr = "<table class=\"rpc-table\" id=\"blocked-clients-table\">" +
			"<tr>" +
			"<th class='rpc-th'>Client</th>" +
			"<th class='rpc-th'>Action</th>" +
			"</tr>";
		data.forEach(element => {
			htmlStr += "<tr>";
			htmlStr += "<td class=\"rpc-td\">" + element + "</td>";
			htmlStr += "<td class=\"rpc-td\"><p onclick='unblockClient(\"" + element +
				"\")' style=\"cursor: pointer;\">unblock</p></td>";
			htmlStr += "</tr>";

		});
		htmlStr += "</table>";
	}
	div = document.getElementById(htmlId);
	div.innerHTML = htmlStr;
	return htmlStr;
}


function printRPCCacheInfoTable(data, htmlId) {
	if (Object.keys(data).length === 0) {
		htmlStr = "<p>RPC cache is empty.</p>";
	} else {
		htmlStr = "<table class=\"rpc-cache-table\" id=\"rpc-cache-table\">" +
			"<tr>" +
			"<th class='rpc-cache-th'>Cache name</th>" +
			"<th class='rpc-cache-th'>Num results</th>" +
			"<th class='rpc-cache-th'>Clear</th>" +
			"</tr>";
		Object.keys(data).forEach(cacheName => {
			htmlStr += "<tr>";
			htmlStr += "<td class=\"rpc-cache-td\">" + cacheName + "</td>";
			htmlStr += "<td class=\"rpc-cache-td\">" + data[cacheName] + "</td>";
			htmlStr += "<td class=\"rpc-cache-td\"><button onclick=\"clearRPCCache('" + cacheName + "\')\">Clear</button></td>";
			htmlStr += "</tr>";

		});
		htmlStr += "</table>";
	}
	div = document.getElementById(htmlId);
	div.innerHTML = htmlStr;
	return htmlStr;
}

function printRPCTable(data, htmlId) {
	let htmlStr = "<table class=\"rpc-table\">";
	htmlStr += "<tr>";
	keys = Object.keys(data[0]);
	Object.keys(data[0]).forEach(element => {
		htmlStr += `<th class="rpc-th" onclick="loadRPCTable('${element}', true)" title="sort" style="cursor: pointer;">${element}</th>`;
	});
	htmlStr += "</tr>";

	data.forEach((element, idx) => {
		htmlStr += "<tr>";
		tdClass = "rpc-td"
		if (element["error"]) {
			tdClass = "rpc-error-td"
		}
		else if (element["deprecated"]) {
			tdClass = "rpc-deprecated-td"
		}
		keys.forEach(key => {
			if (key == "date") {
				date = formateDate(new Date(element[key]))
				htmlStr += `<td class="${tdClass}">${date}</td>`;
			}
			else if (key == "duration") {
				duration = element[key].toFixed(4)
				htmlStr += `<td class="${tdClass}">${duration}</td>`;
			}
			else {
				htmlStr += `<td class="${tdClass}">${element[key]}</td>`;
			}
		});
		htmlStr += "</tr>";
	});

	htmlStr += "</table>";
	div = document.getElementById(htmlId);
	div.innerHTML = htmlStr;
	return htmlStr;
}


var desc = true;
function sortRPCTable(data, sortKey) {
	data = result.sort((a, b) => {
		if (sortKey == "method") {
			var nameA = a[sortKey].toUpperCase();
			var nameB = b[sortKey].toUpperCase();
			if (nameA < nameB) {
				return -1;
			}
			if (nameA > nameB) {
				return 1;
			}
			return 0;
		} else if (sortKey == "date") {
			var dateA = new Date(a[sortKey])
			var dateB = new Date(b[sortKey])
			if (dateA < dateB) {
				return -1;
			}
			if (dateA > dateB) {
				return 1;
			}
			return 0;
		} else if (sortKey == "client") {
			var numA = Number(a[sortKey].split(".").map((num) => (`000${num}`).slice(-3)).join(""));
			var numB = Number(b[sortKey].split(".").map((num) => (`000${num}`).slice(-3)).join(""));
			if (numA < numB) {
				return -1;
			}
			if (numA > numB) {
				return 1;
			}
			return 0;
		} else {
			return Number(a[sortKey]) - Number(b[sortKey]);
		}
	});
	if (desc) {
		data = data.reverse();
		desc = false;
	} else {
		desc = true;
	}
	return data;

}


function outputToHTML(json, id) {
	if (json == undefined) {
		return
	}
	jsonStr = JSON.stringify(json, undefined, 2);
	jsonStr = syntaxHighlight(jsonStr);
	document.getElementById(id).style.visibility = 'visible'
	document.getElementById(id).innerHTML = jsonStr;
}


function decode(html) {
	var txt = document.createElement('textarea');
	txt.innerHTML = html;
	return txt.value;
}


function formateDate(date) {
	year = date.getFullYear();
	month = date.getMonth() + 1;
	dt = date.getDate();
	hour = date.getHours();
	minutes = date.getMinutes();
	seconds = date.getSeconds();

	if (dt < 10) {
		dt = '0' + dt;
	}
	if (month < 10) {
		month = '0' + month;
	}
	if (hour < 10) {
		hour = '0' + hour;
	}
	if (minutes < 10) {
		minutes = '0' + minutes;
	}
	if (seconds < 10) {
		seconds = '0' + seconds;
	}
	date = year + '-' + month + '-' + dt + ' ' + hour + ':' + minutes + ':' + seconds
	return date;
}


var messagebusWS;
var messagebusAutoReconnect = true;
var mbTerminal;

// https://stackoverflow.com/questions/4810841/pretty-print-json-using-javascript
function syntaxHighlightMessage(message) {
	if (typeof message != 'string') {
		message = JSON.stringify(message, undefined, 2);
	}
	message = message.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
	return message.replace(
		/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
		function (match) {
			var cls = 'message_number';
			if (/^"/.test(match)) {
				if (/:$/.test(match)) {
					cls = 'message_key';
				} else {
					cls = 'message_string';
				}
			} else if (/true|false/.test(match)) {
				cls = 'message_boolean';
			} else if (/null/.test(match)) {
				cls = 'message_null';
			}
			return '<span class="' + cls + '">' + match + '</span>';
		});
}

function messagebusConnect() {
	const serverRole = localStorage.getItem("serverRole");
	if (serverRole != "configserver") {
		showNotifcation(`Messagebus unavailable on ${serverRole}`, "messagebus", "error", 10);
		return;
	}
	messagebusAutoReconnect = true;
	let params = []
	let loc = window.location;
	let ws_uri;
	if (loc.protocol == "https:") {
		ws_uri = "wss:";
	} else {
		ws_uri = "ws:";
	}
	ws_uri += "//" + loc.host;
	messagebusWS = new WebSocket(ws_uri + "/messagebus/v1?" + params.join('&'));
	messagebusWS.binaryType = 'arraybuffer';
	messagebusWS.onopen = function () {
		console.log("Messagebus websocket opened");
		showNotifcation("Connected to messagebus", "messagebus", "success", 2);
		document.getElementById("messagebus-connect-disconnect").innerHTML = "Disconnect";
		let dataMessage = {
			type: "channel_subscription_request",
			id: createUUID(),
			sender: "@",
			channel: "service:messagebus",
			created: Date.now(),
			expires: Date.now() + 10000,
			operation: "add",
			channels: [
				"event:app_state_changed",
				"event:user_connected",
				"event:user_disconnected",
				"event:host_created",
				"event:host_updated",
				"event:host_deleted",
				"event:host_connected",
				"event:host_disconnected",
				"event:productOnClient_created",
				"event:productOnClient_updated",
				"event:productOnClient_deleted",
			]
		}
		messagebusSend(dataMessage);
	};
	messagebusWS.onclose = function () {
		console.log("Messagebus websocket closed");
		if (messagebusAutoReconnect) {
			showNotifcation("Messagebus connection lost", "messagebus", "error", 10);
		}
		else {
			showNotifcation("Messagebus connection closed", "messagebus", "success", 2);
		}
		messagebusWS = null;
		if (messagebusAutoReconnect) {
			setTimeout(messagebusConnect, 5000);
		}
		document.getElementById("messagebus-connect-disconnect").innerHTML = "Connect";
	};
	messagebusWS.onerror = function (error) {
		const err = `Messagebus websocket connection error: ${JSON.stringify(error)}`;
		console.error(err);
		//showNotifcation(err, "messagebus", "error", 5);
		messagebusWS = null;
		document.getElementById("messagebus-connect-disconnect").innerHTML = "Connect";
	}
	messagebusWS.onmessage = function (event) {
		const message = msgpack.deserialize(event.data);
		console.debug(message);
		if (message.type == "event") {
			if (message.event == "app_state_changed") {
				outputToHTML(message.data.state, "application-state");
			}
			else if (message.event == "host_connected") {
				const hostId = message.data.host.id;
				if (message.data.host.type == "OpsiClient") {
					if (messagebusConnectedClients.indexOf(hostId) === -1) {
						messagebusConnectedClients.push(hostId);
					}
				}
				else if (message.data.host.type == "OpsiDepotserver") {
					if (messagebusConnectedDepots.indexOf(hostId) === -1) {
						messagebusConnectedDepots.push(hostId);
					}
				}
				updateMessagebusConnectedHosts();
			}
			else if (message.event == "host_disconnected") {
				const hostId = message.data.host.id;
				if (message.data.host.type == "OpsiClient") {
					if (messagebusConnectedClients.indexOf(hostId) !== -1) {
						messagebusConnectedClients.pop(hostId);
					}
				}
				else if (message.data.host.type == "OpsiDepotserver") {
					if (messagebusConnectedDepots.indexOf(hostId) !== -1) {
						messagebusConnectedDepots.pop(hostId);
					}
				}
				updateMessagebusConnectedHosts();
			}
			else if (message.event == "user_connected") {
				const userId = message.data.user.id;
				if (messagebusConnectedUsers.indexOf(userId) === -1) {
					messagebusConnectedUsers.push(userId);
				}
				updateMessagebusConnectedUsers();
			}
			else if (message.event == "user_disconnected") {
				const userId = message.data.user.id;
				if (messagebusConnectedUsers.indexOf(userId) !== -1) {
					messagebusConnectedUsers.pop(userId);
				}
				updateMessagebusConnectedUsers();
			}
		}
		else if (message.type.startsWith("terminal_")) {
			if (mbTerminal && mbTerminal.terminalId == message.terminal_id) {
				if (message.type == "terminal_data_read") {
					mbTerminal.write(message.data);
				}
				else if (message.type == "terminal_open_event" || message.type == "terminal_resize_event") {
					if (message.type == "terminal_open_event") {
						document.getElementById("terminal-channel").value = mbTerminal.terminalChannel = message.back_channel;
					}
					if (mbTerminal.cols != message.cols || mbTerminal.rows != message.rows) {
						mbTerminal.skipResizeEvent = true;
						const dims = mbTerminal._core._renderService.dimensions;
						const width = dims.actualCellWidth * message.cols + 20;
						const height = dims.actualCellHeight * message.rows + 9;
						const terminalContainer = document.getElementById("terminal");
						terminalContainer.style.width = width + 'px';
						terminalContainer.style.height = height + 'px';
						mbTerminal.fitAddon.fit();
					}
				}
				else if (message.type == "terminal_close_event") {
					console.log("Terminal closed");
					mbTerminal.writeln("\r\n\033[1;37m> Terminal closed <\033[0m");
					mbTerminal.write("\033[?25l"); // Make cursor invisible
				}
			}
		}
		else if (message.type == "file_upload_result") {
			document.querySelector('#terminal-xterm .xterm-cursor-layer').classList.remove("upload-active");
			let utf8Encode = new TextEncoder();
			let dataMessage = {
				type: "terminal_data_write",
				id: createUUID(),
				sender: "@",
				channel: mbTerminal.terminalChannel,
				created: Date.now(),
				expires: Date.now() + 10000,
				terminal_id: mbTerminal.terminalId,
				data: utf8Encode.encode(message.path + "\033[D".repeat(message.path.length))
			}
			messagebusSend(dataMessage);
		}
		else if (message.type == "general_error") {
			console.error(message.error);
			showNotifcation(message.error.message + "\n" + message.error.details, "", "error", 10);
		}

		if (
			(!message.type.startsWith("terminal_data") || document.getElementById('messagebus-message-show-terminal-data-messages').checked) &&
			(!message.type.startsWith("file_chunk") || document.getElementById('messagebus-message-show-file-chunk-messages').checked)
		) {
			document.getElementById("messagebus-message-in").innerHTML += "\n" + syntaxHighlightMessage(message);
			if (document.getElementById('messagebus-message-auto-scroll').checked) {
				let el = document.getElementById('messagebus-message-in');
				el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
			}
		}
	}
}

function messagebusDisconnect() {
	messagebusAutoReconnect = false;
	if (!messagebusWS) {
		return;
	}
	messagebusWS.close();
	messagebusWS = null;
}


function messagebusToggleConnect() {
	if (messagebusWS) {
		messagebusDisconnect();
	}
	else {
		messagebusConnect();
	}
}


function messagebusInsertMessageTemplate() {
	let select = document.getElementById("messagebus-message-template-select");
	let val = select.value;
	select.value = "Insert message template";
	let message = {
		type: "",
		id: createUUID(),
		sender: "@",
		channel: "$",
		created: Date.now(),
		expires: Date.now() + 60000
	}
	if (val == "channel_subscription_request") {
		message.type = "channel_subscription_request"
		message.channel = "service:messagebus"
		message.operation = "add"
		message.channels = ["@", "$"]
	}
	else if (val == "trace_request") {
		message.type = "trace_request"
		message.trace = {}
		message.payload = ""
	}
	else if (val == "jsonrpc_request") {
		message.type = "jsonrpc_request"
		message.channel = "service:config:jsonrpc"
		message.rpc_id = "1"
		message.method = ""
		message.params = []
	}
	document.getElementById('messagebus-message-send').value = JSON.stringify(message, undefined, 2);
}


function messagebusSend(message) {
	console.debug(message);
	if (!messagebusWS) {
		showNotifcation("Messagebus not connected.", "messagebus", "error", 3);
		return;
	}
	if (
		(!message.type.startsWith("terminal_data") || document.getElementById('messagebus-message-show-terminal-data-messages').checked) &&
		(!message.type.startsWith("file_chunk") || document.getElementById('messagebus-message-show-file-chunk-messages').checked)
	) {
		document.getElementById("messagebus-message-out").innerHTML += "\n" + syntaxHighlightMessage(message);
		if (document.getElementById('messagebus-message-auto-scroll').checked) {
			let el = document.getElementById('messagebus-message-out');
			el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
		}

	}
	if (message.expires && message.expires <= Date.now()) {
		showNotifcation("Sending expired message", "messagebus", "warning", 5);
	}
	try {
		messagebusWS.send(msgpack.serialize(message));
	}
	catch (error) {
		console.error(error);
		showNotifcation(error, "messagebus", "error", 10);
	}
}


function messagebusSendMessage() {
	messagebusSend(JSON.parse(document.getElementById('messagebus-message-send').value));
}


var messagebusConnectedDepots = [];
var messagebusConnectedClients = [];
var messagebusConnectedUsers = [];
function getMessagebusConnectedClients(callback) {
	let req = ajaxRequest("GET", "/admin/messagebus-connected-clients");
	req.then((result) => {
		//console.debug(result);
		messagebusConnectedDepots = result.depot_ids;
		messagebusConnectedClients = result.client_ids;
		messagebusConnectedUsers = result.user_ids;
		updateMessagebusConnectedHosts();
		updateMessagebusConnectedUsers();
		if (callback) {
			callback();
		}
	});
}

function updateMessagebusConnectedHosts() {
	const depots = document.getElementById("messagebus-connected-depots");
	depots.innerHTML = "";
	const depotList = document.createElement("ul");
	messagebusConnectedDepots.sort();
	messagebusConnectedDepots.forEach(depotId => {
		const depot = document.createElement("li");
		depot.innerHTML = depotId
		depotList.appendChild(depot);
	});
	depots.appendChild(depotList);

	const clients = document.getElementById("messagebus-connected-clients");
	clients.innerHTML = "";
	const clientList = document.createElement("ul");
	messagebusConnectedClients.sort();
	messagebusConnectedClients.forEach(clientId => {
		const client = document.createElement("li");
		client.innerHTML = clientId;
		clientList.appendChild(client);
	});
	clients.appendChild(clientList);
}

function updateMessagebusConnectedUsers() {
	let states = document.querySelectorAll('[id^="user-messagebus-state-"]');
	states.forEach(element => {
		let connected = messagebusConnectedUsers.includes(element.dataset.userId);
		element.innerHTML = connected ? 'connected' : 'not connected';
	});
}

function messagebusToggleAutoScroll() {
	if (document.getElementById('messagebus-message-auto-scroll').checked) {
		let el = document.getElementById('messagebus-message-in');
		el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
		el = document.getElementById('messagebus-message-out');
		el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
	}
}


function fillTerminalSelect() {
	const select = document.getElementById('terminal-host-select');
	select.innerHTML = "";

	let option = document.createElement("option");
	option.text = "Configserver";
	option.dataset.channel = "service:config:terminal";
	select.appendChild(option);

	getMessagebusConnectedClients(function () {
		messagebusConnectedDepots.forEach(depotId => {
			option = document.createElement("option");
			option.text = `Depot ${depotId}`;
			option.dataset.channel = `service:depot:${depotId}:terminal`;
			select.appendChild(option);
		});
	});
	terminalHostSelected();
}


function terminalHostSelected() {
	const option = document.getElementById("terminal-host-select").selectedOptions[0];
	document.getElementById("terminal-channel").value = option.dataset.channel;
	document.getElementById("terminal-id").value = "";
}


function debounce(func, delay = 250) {
	let timerId;
	return (...args) => {
		clearTimeout(timerId);
		timerId = setTimeout(() => {
			func.apply(this, args);
		}, delay);
	};
}

function messagebusTerminalResize(rows, cols) {
	let message = {
		type: "terminal_resize_request",
		id: createUUID(),
		sender: "@",
		channel: mbTerminal.terminalChannel,
		back_channel: mbTerminal.terminalSessionChannel,
		created: Date.now(),
		expires: Date.now() + 10000,
		terminal_id: mbTerminal.terminalId,
		rows: rows,
		cols: cols
	}
	messagebusSend(message);
}
const debouncedMessagebusTerminalResize = debounce(messagebusTerminalResize, 250);

function messagebusConnectTerminal() {
	if (!messagebusWS) {
		showNotifcation("Messagebus not connected.", "messagebus", "error", 3);
		return;
	}
	let terminalChannel = document.getElementById("terminal-channel").value;
	if (!terminalChannel) {
		showNotifcation("Invalid channel.", "messagebus", "error", 3);
		return;
	}

	let terminalId = document.getElementById("terminal-id").value;
	if (!terminalId) {
		terminalId = createUUID();
		document.getElementById("terminal-id").value = terminalId;
	}
	let terminalSessionChannel = `session:${terminalId}`;

	if (mbTerminal) {
		mbTerminal.dispose();
	}

	mbTerminal = new Terminal({
		cursorBlink: true,
		scrollback: 1000,
		fontSize: 14,
		allowProposedApi: true
	});
	mbTerminal.skipResizeEvent = false;
	mbTerminal.terminalId = terminalId;
	mbTerminal.terminalChannel = terminalChannel;
	mbTerminal.terminalSessionChannel = terminalSessionChannel;

	const searchAddon = new SearchAddon.SearchAddon();
	mbTerminal.loadAddon(searchAddon);
	const webLinksAddon = new WebLinksAddon.WebLinksAddon();
	mbTerminal.loadAddon(webLinksAddon);
	mbTerminal.fitAddon = new FitAddon.FitAddon();
	mbTerminal.loadAddon(mbTerminal.fitAddon);

	mbTerminal.open(document.getElementById('terminal-xterm'));

	const webglAddon = new WebglAddon.WebglAddon();
	mbTerminal.loadAddon(webglAddon);

	setTimeout(function () {
		let message = {
			type: "channel_subscription_request",
			id: createUUID(),
			sender: "@",
			channel: "service:messagebus",
			created: Date.now(),
			expires: Date.now() + 10000,
			operation: "add",
			channels: [mbTerminal.terminalSessionChannel]
		}
		messagebusSend(message);

		// document.getElementsByClassName('xterm-viewport')[0].setAttribute("style", "");

		mbTerminal.fitAddon.fit();
		mbTerminal.focus();

		console.log(`size: ${mbTerminal.cols} cols, ${mbTerminal.rows} rows`);

		message = {
			type: "terminal_open_request",
			id: createUUID(),
			sender: "@",
			channel: mbTerminal.terminalChannel,
			back_channel: mbTerminal.terminalSessionChannel,
			created: Date.now(),
			expires: Date.now() + 10000,
			terminal_id: mbTerminal.terminalId,
			cols: mbTerminal.cols,
			rows: mbTerminal.rows
		}
		messagebusSend(message);

		mbTerminal.onData(function (data) {
			let utf8Encode = new TextEncoder();
			let message = {
				type: "terminal_data_write",
				id: createUUID(),
				sender: "@",
				channel: mbTerminal.terminalChannel,
				created: Date.now(),
				expires: Date.now() + 10000,
				terminal_id: mbTerminal.terminalId,
				data: utf8Encode.encode(data)
			}
			messagebusSend(message);
		})
		mbTerminal.onResize(function (event) {
			//console.log("Resize:")
			//console.log(event);
			if (mbTerminal.skipResizeEvent) {
				mbTerminal.skipResizeEvent = false;
			}
			else {
				debouncedMessagebusTerminalResize(event.rows, event.cols);
			}
		});

		const el = document.querySelector('#terminal-xterm .xterm-screen');
		el.ondragenter = function (event) {
			return false;
		};
		el.ondragover = function (event) {
			event.preventDefault();
		}
		el.ondragleave = function (event) {
			return false;
		};
		el.ondrop = function (event) {
			event.preventDefault();
			messagebusFileUpload(event.dataTransfer.files[0], mbTerminal.terminalChannel, mbTerminal.terminalId);
		}
	}, 100);
}

function messagebusFileUpload(file, channel, terminalId = null) {
	console.log("messagebusFileUpload:", file, channel);

	let chunkSize = 100000;
	let fileId = createUUID();
	let chunk = 0;
	let offset = 0;

	var readChunk = function () {
		var reader = new FileReader();
		var blob = file.slice(offset, offset + chunkSize);
		reader.onload = function () {
			document.querySelector('#terminal-xterm .xterm-cursor-layer').classList.add("upload-active");
			//console.log(offset);
			offset += chunkSize;
			chunk += 1;
			const last = (offset >= file.size);

			let message = {
				type: "file_chunk",
				id: createUUID(),
				sender: "@",
				channel: channel,
				created: Date.now(),
				expires: Date.now() + 10000,
				file_id: fileId,
				number: chunk,
				data: new Uint8Array(reader.result),
				last: last
			}
			messagebusSend(message);

			if (!last) {
				// Do not send the next chunk immediately
				// to keep some resources for further messages
				setTimeout(function () {
					readChunk();
				}, 5);
			}
		}
		reader.readAsArrayBuffer(blob);
	}

	document.querySelector('#terminal-xterm .xterm-cursor-layer').classList.add("upload-active");
	let message = {
		type: "file_upload_request",
		id: createUUID(),
		sender: "@",
		channel: channel,
		created: Date.now(),
		expires: Date.now() + 10000,
		file_id: fileId,
		content_type: "application/octet-stream",
		name: file.name,
		size: file.size,
		terminal_id: terminalId
	}
	messagebusSend(message);
	readChunk();
}

var resizeObserver = new ResizeObserver(entries => {
	for (const entry of entries) {
		if (entry.target.id == "terminal") {
			if (mbTerminal) {
				mbTerminal.fitAddon.fit();
			}
		}
	}
});


function toggleFullscreenTerminal(elementId, term) {
	var elem = document.getElementById(elementId);
	if (elem.getAttribute('fullscreenchangelistener') !== 'true') {
		elem.addEventListener('fullscreenchange', (event) => {
			setTimeout(function () {
				term.fitAddon.fit();
			}, 250);
		});
		elem.setAttribute('fullscreenchangelistener', 'true');
	}

	if (elem.requestFullscreen) {
		elem.requestFullscreen();
	}
}


function stopTerminal() {
	if (!mbTerminal) return;

	message = {
		type: "terminal_close_request",
		id: createUUID(),
		sender: "@",
		channel: mbTerminal.terminalChannel,
		created: Date.now(),
		expires: Date.now() + 10000,
		terminal_id: mbTerminal.terminalId
	}
	messagebusSend(message);
	mbTerminal.dispose();
}


function changeTerminalFontSize(val) {
	if (!mbTerminal) return;
	let size = mbTerminal.options.fontSize;
	size += val;
	if (size < 1) { size = 1; }
	mbTerminal.options.fontSize = size;
	mbTerminal.fitAddon.fit();
}


function generateLiceningInfoTable(info, htmlId) {
	htmlStr = "<table id=\"licensing-info-table\">";
	for (const [key, val] of Object.entries(info)) {
		htmlStr += `<tr><td class="licensing-info-key">${key}</td><td>${val}</td></tr>`;
	}
	htmlStr += "</table>";
	div = document.getElementById(htmlId).innerHTML = htmlStr;
}


function generateLiceningDatesTable(dates, activeDate, htmlId) {
	htmlStr = "<table id=\"licensing-dates-table\"><tr><th>Module</th>";
	for (const date of Object.keys(Object.values(dates)[0])) {
		htmlStr += `<th> ${date}</th>`;
	}
	htmlStr += "</tr>";
	for (const [moduleId, dateData] of Object.entries(dates)) {
		htmlStr += `<tr> <td>${moduleId}</td>`;
		for (const [date, moduleData] of Object.entries(dateData)) {
			let title = "";
			for (const [k, v] of Object.entries(moduleData)) {
				title += `${k}: ${v}&#010;`;
			}
			const changed = moduleData['changed'] ? 'changed' : '';
			const active = date == activeDate ? 'active' : 'inactive';
			const text = moduleData['client_number'] == 999999999 ? 'unlimited' : moduleData['client_number'];
			htmlStr += `<td title = "${title}" class="${changed} ${moduleData['state']} ${active}" > ${text}</td>`;
		}
		htmlStr += "</tr>";
	}
	htmlStr += "</table>";
	div = document.getElementById(htmlId).innerHTML = htmlStr;
}


function toggleTabMaximize() {
	tabcontent = document.getElementsByClassName("tabcontent");
	let buttonText = "Maximize";
	for (i = 0; i < tabcontent.length; i++) {
		if (tabcontent[i].style.display == "none") {
			continue;
		}
		if (tabcontent[i].classList.contains("maximize")) {
			tabcontent[i].classList.remove("maximize");
		}
		else {
			tabcontent[i].classList.add("maximize");
			buttonText = "Normal size";
		}
	}
	buttons = document.getElementsByClassName("tab-maximize");
	for (i = 0; i < buttons.length; i++) {
		buttons[i].innerHTML = buttonText;
	}
	if (terminal) terminal.fitAddon.fit();
}


document.onkeydown = function (evt) {
	evt = evt || window.event;
	if (evt.ctrlKey && evt.key == "F11") {
		toggleTabMaximize();
	}
};

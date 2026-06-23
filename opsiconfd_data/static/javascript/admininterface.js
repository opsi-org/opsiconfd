"use strict";

function createUUID() {
	if (typeof crypto.randomUUID === "function") {
		return crypto.randomUUID();
	}
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
		var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
		return v.toString(16);
	});
}


function encodeHTML(str) {
	return String(str).replace(/[\u00A0-\u9999<>\&]/gim, function (i) {
		return '&#' + i.charCodeAt(0) + ';';
	});
}


function textOrEmpty(value) {
	return value == undefined || value == null ? "" : String(value);
}


function createElement(tagName, attributes = {}, children = []) {
	const element = document.createElement(tagName);
	Object.entries(attributes).forEach(([name, value]) => {
		if (value == undefined || value == null || value === false) {
			return;
		}
		if (name === "className") {
			element.className = value;
		}
		else if (name === "dataset") {
			Object.entries(value).forEach(([key, datasetValue]) => {
				element.dataset[key] = textOrEmpty(datasetValue);
			});
		}
		else if (name === "style") {
			Object.assign(element.style, value);
		}
		else if (name.startsWith("on") && typeof value === "function") {
			element.addEventListener(name.substring(2), value);
		}
		else if (value === true) {
			element.setAttribute(name, name);
		}
		else {
			element.setAttribute(name, value);
		}
	});
	children.forEach(child => {
		if (child == undefined || child == null) {
			return;
		}
		element.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
	});
	return element;
}


function replaceContent(elementOrId, children = []) {
	const element = typeof elementOrId === "string" ? document.getElementById(elementOrId) : elementOrId;
	if (!element) {
		return null;
	}
	element.replaceChildren(...children.map(child => child instanceof Node ? child : document.createTextNode(String(child))));
	return element;
}


function showTableLoading(elementOrId, message = "Loading...") {
	const element = typeof elementOrId === "string" ? document.getElementById(elementOrId) : elementOrId;
	if (!element) {
		return null;
	}
	element.classList.add("table-loading-container");
	if (element.querySelector(":scope > .table-loading-overlay")) {
		return element;
	}
	const overlay = createElement("div", { className: "table-loading-overlay" }, [
		createElement("div", { className: "table-loading-content" }, [
			createElement("div", { className: "table-loading-spinner" }),
			createElement("span", {}, [message])
		])
	]);
	element.appendChild(overlay);
	return element;
}


function createTable(className, headerClasses, columns, rows) {
	const table = createElement("table", { className: className });
	const headerRow = createElement("tr");
	columns.forEach(column => {
		headerRow.appendChild(createElement("th", { className: headerClasses }, [column.label]));
	});
	table.appendChild(headerRow);
	rows.forEach(rowData => {
		const row = createElement("tr");
		columns.forEach(column => {
			const cellClassName = typeof column.cellClassName === "function" ? column.cellClassName(rowData) : column.cellClassName;
			const cell = createElement("td", { className: cellClassName || "" });
			const content = typeof column.render === "function" ? column.render(rowData) : rowData[column.key];
			if (Array.isArray(content)) {
				cell.append(...content.map(child => child instanceof Node ? child : document.createTextNode(String(child))));
			}
			else if (content instanceof Node) {
				cell.appendChild(content);
			}
			else {
				cell.textContent = textOrEmpty(content);
			}
			row.appendChild(cell);
		});
		table.appendChild(row);
	});
	return table;
}


function showNotification(message, group = "", type = "success", seconds = 10) {
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
	msg.textContent = textOrEmpty(message);
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
	const params = { "type": type }
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
		showNotification(`Error setting application state: ${error.message}`, "app-state", "error", 10);
	});
}


function createBackup() {
	const button = document.getElementById("create-backup-create-button");
	button.classList.add("loading");
	const config_files = document.getElementById("create-backup-config-files").checked;
	const redis_data = document.getElementById("create-backup-redis-data").checked;
	const maintenance_mode = document.getElementById("create-backup-maintenance-mode").checked;
	const password = document.getElementById("create-backup-password").value;
	const req = rpcRequest("service_createBackup", [config_files, redis_data, maintenance_mode, password, "file_id"]);
	req.then((response) => {
		console.debug(response);
		if (response.error) {
			showNotification(`Failed to create backup: ${response.error.message}`, "backup", "error", 30);
		}
		else {
			showNotification("Backup successfully created", "backup", "success", 5);
			const link = document.createElement('a');
			link.setAttribute('href', `/file-transfer/${response.result}?delete=true`);
			link.style.display = 'none';
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);
		}
		button.classList.remove("loading");
	}, (error) => {
		console.error(error);
		showNotification(`Failed to create backup: ${error.message || JSON.stringify(error)}`, "backup", "error", 30);
		button.classList.remove("loading");
	});
}


function restoreBackup() {
	const file = document.getElementById("restore-backup-file").files[0];
	if (!file) {
		showNotification("Backup file not provided", "restore", "error", 3);
		return;
	}

	const serverIDSelect = document.querySelector('input[name="restore-backup-server-id-select"]:checked').value;
	let serverID = document.getElementById("restore-backup-server-id").value;
	if (serverIDSelect == "backup" || serverIDSelect == "local") {
		serverID = serverIDSelect;
	}
	if (!serverID) {
		showNotification("Server ID not provided", "restore", "error", 3);
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
		const redisData = document.getElementById("restore-backup-redis-data").checked;
		const batch = true;
		const req = rpcRequest(
			"service_restoreBackup", [response.file_id, configFiles, redisData, serverID, password, batch]
		);
		req.then((response) => {
			console.debug(response);
			if (response.error) {
				showNotification(`Failed to restore backup: ${response.error.message}`, "restore", "error", 30);
			}
			else {
				showNotification("Backup successfully restored", "restore", "success", 5);
			}
			button.classList.remove("loading");
		});
	}, (error) => {
		console.error(error);
		showNotification(`Failed to restore backup: ${error.message || JSON.stringify(error)}`, "restore", "error", 30);
		button.classList.remove("loading");
	});
}


function unblockAllClients() {
	let req = ajaxRequest("POST", "/admin/unblock-all");
	req.then((result) => {
		outputToHTML(result, "json-result");
		renderUnblockResult(result, "text-result");
		loadBlockedClientsTable()
		return result
	});
}


function unblockClient(ip) {
	if (validateIpAddress(ip)) {
		let req = ajaxRequest("POST", "/admin/unblock-client", { "client_addr": ip });
		req.then((result) => {
			outputToHTML(result, "json-result");
			renderUnblockResult(result, "text-result");
			loadBlockedClientsTable()
			return result
		});
	}
}


function loadRPCCacheInfo() {
	let req = ajaxRequest("GET", "/redis-interface/load-rpc-cache-info");
	req.then((result) => {
		renderRPCCacheInfoTable(result.result, "rpc-cache-info-div");
	});
}


function clearRPCCache(cacheName = null) {
	let req = ajaxRequest("POST", "/redis-interface/clear-rpc-cache", { "cache_name": cacheName });
	req.then((result) => {
		loadRPCCacheInfo();
	});
}


function clearDeprecatedCalls() {
	let req = ajaxRequest("DELETE", "/redis-interface/deprecated-calls");
	req.then((result) => {
		outputToHTML(result, "redis-result");
	});
}


function getDeprecatedCalls() {
	let req = ajaxRequest("GET", "/redis-interface/deprecated-calls");
	req.then((result) => {
		outputToHTML(result, "redis-result");
	});
}


function loadDepotTable() {
	let req = ajaxRequest("GET", "/admin/depots");
	req.then((result) => {
		renderDepotTable(result, "depots-table-div");
		return result
	});
}


function createDepot() {
	const depotId = document.getElementById("create-depot-id").value;
	const depotDescription = document.getElementById("create-depot-description").value;
	const masterDepot = document.getElementById("create-depot-master").checked;
	let req = ajaxRequest("POST", "/admin/depot-create", { "id": depotId, "description": depotDescription, "master": masterDepot });
	req.then((result) => {
		loadDepotTable();
	}, (error) => {
		console.error(error);
		showNotification(`Failed to create depot: ${error.message}`, "create-depot", "error", 10);
	});
}


function loadBlockedClientsTable() {
	let req = ajaxRequest("GET", "/admin/blocked-clients");
	req.then((result) => {
		renderClientTable(result, "blocked-clients-div");
		return result
	});
}


function loadLockedProductsTable() {
	let req = ajaxRequest("GET", "/admin/locked-products-list");
	req.then((result) => {
		renderLockedProductsTable(result, "locked-products-table-div");
		return result
	});
}


function unlockProduct(product, depots = null) {
	let req = ajaxRequest("POST", "/admin/products/" + product + "/unlock", { "depots": depots.split(",") });
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

function loadRedisDebugKeys() {
	let req = ajaxRequest("POST", "/redis-interface/redis-debug-keys", { "prefix": document.getElementById("redis-cmd").value });
	req.then((result) => {
		outputToHTML(result, "redis-result");
		return result
	});
}

function loadSessionTable(showLoading = true) {
	if (showLoading) {
		showTableLoading("session-table-div");
	}
	let req = ajaxRequest("GET", "/admin/session-list");
	req.then((result) => {
		renderSessionTable(result, "session-table-div");
		return result
	});
}

let rpcTableSort = { sortBy: "rpc_num", sortDesc: true };

function loadRPCTable(sortBy, sortDesc) {
	if (sortBy !== undefined) {
		rpcTableSort.sortBy = sortBy;
	}
	if (sortDesc !== undefined) {
		rpcTableSort.sortDesc = sortDesc;
	}
	const params = new URLSearchParams({ "sort_by": rpcTableSort.sortBy, "sort_desc": rpcTableSort.sortDesc });
	showTableLoading("rpc-table-div");
	let req = ajaxRequest("GET", `/admin/rpc-list?${params.toString()}`);
	req.then((result) => {
		if (result.length == 0) {
			document.getElementById("rpc-table-div").textContent = "No rpcs found.";
			return null
		}
		renderRPCTable(result, "rpc-table-div");
		return result;
	});
}


let auditLogTableSort = { sortBy: "created", sortDesc: true };
let auditLogUsernameFilterTimer;

function onAuditLogUsernameFilterInput() {
	clearTimeout(auditLogUsernameFilterTimer);
	auditLogUsernameFilterTimer = setTimeout(() => loadAuditLogTable(), 300);
}

function loadAuditLogTable(sortBy, sortDesc) {
	if (sortBy !== undefined) {
		auditLogTableSort.sortBy = sortBy;
	}
	if (sortDesc !== undefined) {
		auditLogTableSort.sortDesc = sortDesc;
	}
	const filter = {};
	const eventTypeFilter = document.getElementById("audit-log-event-type-filter");
	if (eventTypeFilter && eventTypeFilter.value) {
		filter.eventType = eventTypeFilter.value;
	}
	const usernameFilter = document.getElementById("audit-log-username-filter");
	if (usernameFilter && usernameFilter.value) {
		filter.username = `*${usernameFilter.value.toLowerCase()}*`;
	}
	const actorTypeFilter = document.getElementById("audit-log-actor-type-filter");
	if (actorTypeFilter && actorTypeFilter.value) {
		filter.actorType = actorTypeFilter.value;
	}
	const requestBody = {
		filter: filter,
		orderBy: { [auditLogTableSort.sortBy]: auditLogTableSort.sortDesc ? "desc" : "asc" },
		limit: 500,
	};
	showTableLoading("audit-log-table-div");
	let req = ajaxRequest("POST", "/admin/audit-log", requestBody);
	req.then((result) => {
		renderAuditLogTable(result, "audit-log-table-div");
		return result;
	});
}


let confirmOverlayState = {
	onConfirm: null,
	onCancel: null
};

function initConfirmOverlay() {
	const overlay = document.getElementById("confirm-overlay");
	if (!overlay) {
		return;
	}
	const cancelButton = document.getElementById("confirm-overlay-cancel");
	const confirmButton = document.getElementById("confirm-overlay-confirm");

	overlay.addEventListener("click", (event) => {
		if (event.target === overlay) {
			hideDialogOverlay("cancel");
		}
	});

	cancelButton.addEventListener("click", () => {
		hideDialogOverlay("cancel");
	});

	confirmButton.addEventListener("click", () => {
		hideDialogOverlay("confirm");
	});

	document.addEventListener("keydown", (event) => {
		if (event.key === "Escape" && overlay.classList.contains("active")) {
			hideDialogOverlay("cancel");
		}
	});
}

function showDialogOverlay({ title, message = "", bodyHtml, bodyElement, confirmLabel = "Confirm", cancelLabel = "Cancel", onConfirm, onCancel }) {
	const overlay = document.getElementById("confirm-overlay");
	const titleEl = document.getElementById("confirm-overlay-title");
	const messageEl = document.getElementById("confirm-overlay-message");
	const bodyEl = document.getElementById("confirm-overlay-body");
	const cancelButton = document.getElementById("confirm-overlay-cancel");
	const confirmButton = document.getElementById("confirm-overlay-confirm");

	if (!overlay || !titleEl || !messageEl || !bodyEl || !cancelButton || !confirmButton) {
		return;
	}

	confirmOverlayState = {
		onConfirm: onConfirm || null,
		onCancel: onCancel || null
	};

	titleEl.textContent = title || "Confirm";
	messageEl.textContent = textOrEmpty(message);
	bodyEl.replaceChildren();
	if (bodyElement) {
		bodyEl.appendChild(bodyElement);
	}
	else if (bodyHtml) {
		bodyEl.innerHTML = bodyHtml;
	}
	cancelButton.style.display = "";
	confirmButton.style.display = "";
	if (cancelLabel) {
		cancelButton.textContent = cancelLabel;
	}
	else {
		cancelButton.style.display = "none";
	}

	if (confirmLabel) {
		confirmButton.textContent = confirmLabel;
	}
	else {
		confirmButton.style.display = "none";
	}

	overlay.classList.add("active");
}

function hideDialogOverlay(action = "cancel") {
	const overlay = document.getElementById("confirm-overlay");
	if (!overlay) {
		return;
	}

	overlay.classList.remove("active");

	const onConfirm = confirmOverlayState.onConfirm;
	const onCancel = confirmOverlayState.onCancel;
	confirmOverlayState = { onConfirm: null, onCancel: null };

	if (action === "confirm" && onConfirm) {
		onConfirm();
	}
	else if (action === "cancel" && onCancel) {
		onCancel();
	}
}


function updateMultiFactorAuth(userId, type) {
	let req = ajaxRequest("POST", "/admin/update-multi-factor-auth", { "user_id": userId, "type": type });
	req.then((result) => {
		if (result) {
			let html = `<div style="line-height: 1.0; font-family: monospace; white-space: pre;">${result}</div>`;
			html += "<p>Your multi-factor secret has been changed.<br>";
			html += "Please use an app like Google Authenticator and scan the QR code displayed.<br>";
			html += "The app will then generate a new one-time password every 30 seconds.<br>";
			html += "Without this password you will not be able to log in to the OPSI server anymore.</p>";
			showDialogOverlay({
				title: `Multi-factor authentication for ${userId}`,
				bodyHtml: html,
				confirmLabel: "Done",
				cancelLabel: null
			});
		}
		loadUserTable();
	});
}

function showChangePasswordDialog(userId, errorMessage = null) {
	let html = "";
	if (errorMessage) {
		html += `<p style="color:red;">${errorMessage}</p>`;
	}
	html += `<form action="javascript:void(0);">`;
	html += `<label for="change-password-new-password" style="width: 150px; display: inline-block;">New password:</label>`;
	html += `<input type="password" id="change-password-new-password" /><br/>`;
	html += `<label for="change-password-confirm-password" style="width: 150px; display: inline-block;">Confirm password:</label>`;
	html += `<input type="password" id="change-password-confirm-password" /><br/>`;
	html += `</form>`;

	showDialogOverlay({
		title: `Change password of user ${userId}`,
		bodyHtml: html,
		confirmLabel: "Change password",
		cancelLabel: "Cancel",
		onConfirm: () => changeInternalUserPassword(
			userId,
			document.getElementById('change-password-new-password').value,
			document.getElementById('change-password-confirm-password').value,
		)
	});
}

function changeInternalUserPassword(userId, password = null, confirmPassword = null) {
	if (!password || password !== confirmPassword) {
		let errorMessage = null;
		if (password !== confirmPassword) {
			errorMessage = "The provided passwords do not match. Please try again.";
		}
		showChangePasswordDialog(userId, errorMessage);
	}
	else {
		let req = ajaxRequest("POST", "/admin/set-internal-user-password", { "user_id": userId, "password": password });
		req.then((result) => {
			showNotification("New password successfully set", "user-edit", "success", 3);
			loadUserTable();
		}, (error) => {
			let errorMessage = `Failed to set user password: ${error.message || error.detail || JSON.stringify(error)}`;
			showChangePasswordDialog(userId, errorMessage);
			showNotification(errorMessage, "user-edit", "error", 10);
			loadUserTable();
		});
	}
}

function updateUserTokenAuth(userId, enable) {
	let req = ajaxRequest("POST", "/admin/update-user-token-auth", { "user_id": userId, "enable": enable });
	req.then((result) => {
		showNotification(`Token authentication ${enable ? "enabled" : "disabled"} successfully`, "user-edit", "success", 3);
		if (enable) {
			let html = "<p>Token authentication is now enabled.<br>";
			html += "Please store the following token securely as it will not be shown again:<br><br>";
			html += `<strong>${result}</strong></p>`;
			showDialogOverlay({
				title: `Token authentication for ${userId}`,
				bodyHtml: html,
				confirmLabel: "Done",
				cancelLabel: null
			});
		}
		loadUserTable();
	}, (error) => {
		let errorMessage = `Failed to update token authentication: ${error.message || error.detail || JSON.stringify(error)}`;
		showNotification(errorMessage, "user-edit", "error", 10);
		loadUserTable();
	});
}


function showCreateUserDialog(userId, admin, readonly, errorMessage = null) {
	let html = "";
	if (errorMessage) {
		html += `<p style="color:red;">${errorMessage}</p>`;
	}
	html += `<form action="javascript:void(0);">`;
	html += `<label for="new-user-username" style="width: 150px; display: inline-block;">Username:</label>`;
	html += `<input type="text" id="new-user-username" autocomplete="username" value="${userId || ''}" /><br/>`;
	html += `<label for="new-user-new-password" style="width: 150px; display: inline-block;">Password:</label>`;
	html += `<input type="password" id="new-user-new-password" autocomplete="new-password" /><br/>`;
	html += `<label for="new-user-confirm-password" style="width: 150px; display: inline-block;">Confirm password:</label>`;
	html += `<input type="password" id="new-user-confirm-password" autocomplete="new-password" /><br/>`;
	html += `<input type="checkbox" id="new-user-admin" ${admin ? "checked" : ""} onchange="document.getElementById('new-user-readonly').checked = !this.checked;" /> Admin<br/>`;
	html += `<input type="checkbox" id="new-user-readonly" ${readonly ? "checked" : ""} onchange="document.getElementById('new-user-admin').checked = !this.checked;" /> Readonly<br/>`;
	html += `</form>`;

	showDialogOverlay({
		title: "Create new user",
		bodyHtml: html,
		confirmLabel: "Create user",
		cancelLabel: "Cancel",
		onConfirm: () => createUser(
			document.getElementById('new-user-username').value,
			document.getElementById('new-user-new-password').value,
			document.getElementById('new-user-confirm-password').value,
			document.getElementById('new-user-admin').checked,
			document.getElementById('new-user-readonly').checked
		)
	});
}

function createUser(userId = null, password = null, confirmPassword = null, admin = true, readonly = false) {
	if (!userId || password !== confirmPassword) {
		let errorMessage = null;
		if (password !== confirmPassword) {
			errorMessage = "The provided passwords do not match. Please try again.";
		}
		showCreateUserDialog(userId, admin, readonly, errorMessage);
	}
	else {
		let req = ajaxRequest("POST", "/admin/create-user", { "user_id": userId, "password": password, "admin": admin, "readonly": readonly });
		req.then((result) => {
			showNotification("New user successfully created", "user-edit", "success", 3);
			loadUserTable();
		}, (error) => {
			let errorMessage = `Failed to create user: ${error.message || error.detail || JSON.stringify(error)}`;
			showCreateUserDialog(userId, admin, readonly, errorMessage);
			showNotification(errorMessage, "user-edit", "error", 10);
			loadUserTable();
		});
	}
}


function deleteUser(userId, confirmed = false) {
	if (!confirmed) {
		showDialogOverlay({
			title: `Delete user ${userId}?`,
			message: `Are you sure you want to delete the user ${userId}? This action cannot be undone.`,
			confirmLabel: "Delete user",
			cancelLabel: "Cancel",
			onConfirm: () => deleteUser(userId, true)
		});
	}
	else {
		let req = ajaxRequest("POST", "/admin/delete-user", { "user_id": userId });
		req.then((result) => {
			showNotification("User successfully deleted", "user-edit", "success", 3);
			loadUserTable();
		}, (error) => {
			let errorMessage = `Failed to delete user: ${error.message || error.detail || JSON.stringify(error)}`;
			showNotification(errorMessage, "user-edit", "error", 10);
			loadUserTable();
		});
	}
}

function closeAllActionMenus() {
	document.querySelectorAll(".action-menu-items").forEach(element => {
		element.style.display = "none";
		element.style.visibility = "";
	});
}

function closeActionMenu(menuId) {
	const menu = document.getElementById(menuId);
	if (!menu) {
		return;
	}
	menu.style.display = "none";
}

function positionActionMenu(menu, button) {
	const buttonRect = button.getBoundingClientRect();
	menu.style.visibility = "hidden";
	menu.style.display = "block";

	const menuRect = menu.getBoundingClientRect();
	const margin = 8;
	const belowTop = buttonRect.bottom + 4;
	const aboveTop = buttonRect.top - menuRect.height - 4;
	let top = belowTop;
	if (belowTop + menuRect.height > window.innerHeight - margin && aboveTop >= margin) {
		top = aboveTop;
	}
	top = Math.max(margin, Math.min(top, window.innerHeight - menuRect.height - margin));

	let left = buttonRect.right - menuRect.width;
	left = Math.max(margin, Math.min(left, window.innerWidth - menuRect.width - margin));

	menu.style.top = `${top}px`;
	menu.style.left = `${left}px`;
	menu.style.visibility = "visible";
}

function toggleActionMenu(menuId, button) {
	const menu = document.getElementById(menuId);
	if (!menu) {
		return;
	}
	const isOpen = menu.style.display === "block";
	closeAllActionMenus();
	if (!isOpen && button) {
		positionActionMenu(menu, button);
	}
}

function buildActionMenu(menuId, actions) {
	const existingMenu = document.getElementById(menuId);
	if (existingMenu) {
		existingMenu.remove();
	}
	const menu = createElement("div", { className: "action-menu", style: { position: "relative", display: "inline-block" } });
	const button = createElement("button", { type: "button", className: "action-menu-button", onclick: event => toggleActionMenu(menuId, event.currentTarget) }, ["Actions"]);
	const items = createElement("div", { id: menuId, className: "action-menu-items" });
	actions.forEach(action => {
		const item = createElement("div", { className: "action-menu-item", role: "menuitem", tabindex: "0" }, [action.label]);
		const runAction = () => {
			action.onClick();
			closeActionMenu(menuId);
		};
		item.addEventListener("click", runAction);
		item.addEventListener("keydown", (event) => {
			if (event.key === "Enter" || event.key === " ") {
				event.preventDefault();
				runAction();
			}
		});
		items.appendChild(item);
	});
	menu.appendChild(button);
	document.body.appendChild(items);
	return menu;
}

document.addEventListener("click", (event) => {
	if (!event.target.closest(".action-menu")) {
		closeAllActionMenus();
	}
});

window.addEventListener("resize", closeAllActionMenus);
window.addEventListener("scroll", closeAllActionMenus, true);


function renderUserTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	document.querySelectorAll('.action-menu-items[id^="user-actions-"]').forEach(element => element.remove());
	const content = [];
	if (data.length == 0) {
		content.push(createElement("p", {}, ["No users found."]));
	} else {
		data.sort((a, b) => (a.id > b.id) ? 1 : -1);
		const table = createElement("table", { className: "user-table", id: "user-table" });
		const headerRow = createElement("tr");
		[
			"User-ID",
			"Groups",
			"Last login",
			"Internal Authentication",
			"Token Authentication"
		].forEach(label => headerRow.appendChild(createElement("th", { className: "user-th" }, [label])));
		if (multiFactorAuth == "totp_optional" || multiFactorAuth == "totp_mandatory") {
			headerRow.appendChild(createElement("th", { className: "user-th" }, ["MFA state"]));
		}
		headerRow.appendChild(createElement("th", { className: "user-th" }, ["Messagebus"]));
		headerRow.appendChild(createElement("th", { className: "user-th" }, ["Actions"]));
		table.appendChild(headerRow);
		data.forEach(user => {
			if (!user.mfaState) {
				user.mfaState = "inactive";
			}
			let actions = [];
			const row = createElement("tr");
			row.appendChild(createElement("td", { className: "user-td" }, [user.id]));
			row.appendChild(createElement("td", { className: "user-td", style: { maxWidth: "150px" } }, [(user.groups || []).join(", ")]));
			row.appendChild(createElement("td", { className: "user-td" }, [user.lastLogin ? formatDate(parseUTCDate(user.lastLogin)) : "never"]));
			row.appendChild(createElement("td", { className: "user-td" }, [user.internal_auth ? "yes" : "no"]));
			row.appendChild(createElement("td", { className: "user-td" }, [user.token_auth ? "yes" : "no"]));
			if (databaseAuth) {
				actions.push({ label: "Change password", onClick: () => changeInternalUserPassword(user.id) });
				if (user.token_auth) {
					actions.push({ label: "Remove Authentication Token", onClick: () => updateUserTokenAuth(user.id, false) });
				}
				actions.push({ label: "New Authentication Token", onClick: () => updateUserTokenAuth(user.id, true) });
			}
			if (multiFactorAuth == "totp_optional" || multiFactorAuth == "totp_mandatory") {
				let cls = "mfa-" + (user.mfaState == "inactive" ? "inactive" : "active");
				if (multiFactorAuth == "totp_mandatory" && user.mfaState == "inactive") {
					cls += "-warn";
				}
				row.appendChild(createElement("td", { className: `user-td ${cls}` }, [user.mfaState]));
				actions.push({ label: "Generate new secret and activate TOTP", onClick: () => updateMultiFactorAuth(user.id, "totp") });
				if (multiFactorAuth == "totp_optional" && user.mfaState != "inactive") {
					actions.push({ label: "Deactivate MFA", onClick: () => updateMultiFactorAuth(user.id, "inactive") });
				}
			}
			if (databaseAuth) {
				actions.push({ label: "Delete user", onClick: () => deleteUser(user.id) });
			}
			let connected = messagebusConnectedUsers.includes(user.id);
			let cls = "user-" + (connected ? "connected" : "not-connected");
			row.appendChild(createElement("td", {
				className: `user-td ${cls}`,
				id: `user-messagebus-state-${user.id}`,
				dataset: { userId: user.id }
			}, [connected ? "connected" : "not connected"]));
			if (actions.length > 0) {
				const menuId = `user-actions-${user.id}`;
				row.appendChild(createElement("td", { className: "user-td" }, [buildActionMenu(menuId, actions)]));
			}
			else {
				row.appendChild(createElement("td", { className: "user-td" }, ["-"]));
			}
			table.appendChild(row);
		});
		content.push(table);
	}
	if (databaseAuth) {
		content.push(createElement("button", { onclick: () => createUser() }, ["Create new user"]));
	}
	container.replaceChildren(...content);
	return container.innerHTML;
}

function loadUserTable() {
	showTableLoading("user-table-div");
	let req = ajaxRequest("GET", "/admin/user-list");
	req.then((result) => {
		renderUserTable(result, "user-table-div");
		return result
	});
}

function loadAddons() {
	let req = ajaxRequest("GET", "/admin/addons");
	req.then((result) => {
		renderAddonTable(result, "addon-table-div");
		return result
	});
}

function loadFailedAddons() {
	let req = ajaxRequest("GET", "/admin/addons/failed");
	req.then((result) => {
		renderFailedAddonTable(result, "failed-addon-table-div");
		return result
	});
}


function installAddon() {
	const file = document.getElementById("addon-file").files[0];
	if (!file) {
		showNotification(`Addon file not provided`, "addon", "error", 3);
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
		showNotification("Addon successfully installed", "addon", "success", 3);
	}, (error) => {
		if (button) {
			button.classList.remove("loading");
		}
		console.log(error);
		console.warn(error.status, error.details);
		showNotification(`Failed to install addon: ${error.message || JSON.stringify(error)}`, "addon", "error", 30);
	});
}

function deleteClientSessions() {
	const body = {
		"client_addr": sessionAddr.value
	};
	if (validateIpAddress(sessionAddr.value)) {
		let req = ajaxRequest("POST", "/admin/delete-client-sessions", body);
		req.then((result) => {
			outputToHTML(result, "json-result");
			renderUnblockResult(result, "text-result");
			return result

		}, (error) => {
			console.log(error);
		});
	}
}


function loadServerInfo() {
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


function reloadConfig() {
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
							<td><input class=\"jsonrpc-param-input\" type=\"text\" id=\"" + param + "\" name=\"" + param + "\" oninput=\"updateRequestJSONPreview(this.name,this.value)\" /></td> \
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
	updateRequestJSONPreview();
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
	for (let i = 0; i < inputs.length; i++) {
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
			document.getElementById("jsonrpc-request-error").textContent = `${name}: ${e}`;
		}
	}

	apiJSON.params = parameter;
	return apiJSON;
}


function updateRequestJSONPreview(name, value) {
	let apiJSON = createRequestJSON();
	outputToHTML(apiJSON, "jsonrpc-request");
}


function callJSONRPC() {
	let inputs = document.getElementById("tab-rpc-interface").getElementsByTagName("input");
	for (let i = 0; i < inputs.length; i++) {
		let name = inputs[i].name.trim();
		let value = inputs[i].value.trim();

		if (!value && name.substring(0, 1) != "*") {
			const error = `Mandatory field '${inputs[i].name}' is empty`;
			showNotification(error, "jsonrpc", "error", 3);
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
		document.getElementById("jsonrpc-response-info").textContent = `Request processing: ${serverTimings.request_processing} ms`;
		outputToHTML(result.data, "jsonrpc-result");
		return result;
	}).finally(() => {
		document.getElementById("jsonrpc-execute-button").disabled = false;
	});
}


function loadLicensingInfo() {
	let req = ajaxRequest("GET", "/admin/licensing_info");
	req.then((result) => {
		if (typeof result.module_dates != "undefined" && Object.keys(result.module_dates).length > 0) {
			generateLicensingInfoTable(result.info, "licensing-info");
			generateLicensingDatesTable(result.module_dates, result.active_date, "licensing-dates");
		} else {
			replaceContent("licensing-info", [createElement("p", {}, ["No licenses available."])]);
			replaceContent("licensing-dates");
		}
	});
}


function uploadLicense(files) {
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


function renderUnblockResult(json, id) {
	if (json == undefined) {
		return
	}
	let text = "";
	if (json["status"] == 200) {
		const data = json["data"]
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
	document.getElementById(id).textContent = text;
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

function validateIpAddress(ipaddress) {
	if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
		.test(ipaddress)) {
		return (true)
	}
	showNotification("You have entered an invalid IP address.", "", "error", 3);
	return (false)
}

function renderSessionTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (data.length == 0) {
		replaceContent(container, [createElement("p", {}, ["No sessions found."])]);
	} else {
		data.sort((a, b) => (a.session_id > b.session_id) ? 1 : -1);
		const table = createTable("session-table", "session-th", [
			{ label: "Address", cellClassName: "session-td", render: row => row.address },
			{ label: "Session ID", cellClassName: "session-td", render: row => row.session_id },
			{ label: "User-Agent", cellClassName: "session-td", render: row => row.user_agent },
			{ label: "Username", cellClassName: "session-td", render: row => row.username },
			{ label: "Authenticated", cellClassName: "session-td", render: row => row.authenticated },
			{ label: "Authentication methods", cellClassName: "session-td", render: row => row.auth_methods },
			{ label: "Validity", cellClassName: "session-td", render: row => Math.round(row.validity) }
		], data);
		table.id = "session-table";
		replaceContent(container, [table]);
	}
	return container.innerHTML;
}


function renderLockedProductsTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (data == undefined) {
		replaceContent(container, [createElement("p", {}, ["No locked Products found."])]);
	}
	else if (Object.keys(data).length === 0) {
		replaceContent(container, [createElement("p", {}, ["No locked Products found."])]);
	} else {
		const rows = Object.entries(data).map(([product, depots]) => ({ product, depots }));
		const table = createTable("locked-products-table", "locked-products-th", [
			{ label: "Product", cellClassName: "locked-products-td", render: row => row.product },
			{ label: "Depots", cellClassName: "locked-products-td", render: row => row.depots.flatMap(depot => [depot, createElement("br")]) },
			{ label: "Action", cellClassName: "locked-products-td", render: row => createElement("input", { type: "button", value: "Unlock", onclick: () => unlockProduct(row.product, row.depots.join(",")) }) }
		], rows);
		table.id = "locked-products-table";
		replaceContent(container, [table]);
	}
	return container.innerHTML;
}


function renderAddonTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (data == undefined) {
		replaceContent(container, [createElement("p", {}, ["No addons loaded."])]);
	}
	else if (data.length == 0) {
		replaceContent(container, [createElement("p", {}, ["No addons loaded."])]);
	} else {
		const table = createTable("addon-table", "addon-th", [
			{ label: "Addon ID", cellClassName: "addon-td", render: row => createElement("a", { href: row.path, target: "_blank", rel: "noopener noreferrer" }, [row.id]) },
			{ label: "Name", cellClassName: "addon-td", render: row => row.name },
			{ label: "Version", cellClassName: "addon-td", render: row => row.version },
			{ label: "Install path", cellClassName: "addon-td", render: row => row.install_path }
		], data);
		table.id = "addon-table";
		replaceContent(container, [table]);
	}
	return container.innerHTML;
}

function renderFailedAddonTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (data == undefined) {
		replaceContent(container);
	}
	else if (data.length == 0) {
		replaceContent(container);
	} else {
		const table = createTable("failed-addon-table", "failed-addon-th", [
			{ label: "Name", cellClassName: "failed-addon-td", render: row => row.name },
			{ label: "Path", cellClassName: "failed-addon-td", render: row => row.addon_path },
			{ label: "Error", cellClassName: "error-addon-td", render: row => row.error }
		], data);
		table.id = "failed-addon-table";
		replaceContent(container, [createElement("h4", {}, ["Addons that failed to load:"]), table]);
	}
	return container.innerHTML;
}


function renderClientTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (data == undefined) {
		data = []
	}
	if (data.length == 0) {
		replaceContent(container, [createElement("p", {}, ["No clients are blocked by the server."])]);
	} else {
		const rows = data.map(client => ({ client }));
		const table = createTable("rpc-table", "rpc-th", [
			{ label: "Client", cellClassName: "rpc-td", render: row => row.client },
			{ label: "Action", cellClassName: "rpc-td", render: row => createElement("button", { onclick: () => unblockClient(row.client) }, ["Unblock"]) }
		], rows);
		table.id = "blocked-clients-table";
		replaceContent(container, [table]);
	}
	return container.innerHTML;
}


function toggleTextSecurityVisibility(element) {
	element.style.webkitTextSecurity = element.style.textSecurity =
		((element.style.textSecurity == "disc" || element.style.webkitTextSecurity == "disc") ? "none" : "disc");
}


function renderDepotTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (data == undefined) {
		data = []
	}
	if (data.length == 0) {
		replaceContent(container, [createElement("p", {}, ["No depots."])]);
	} else {
		const table = createElement("table", { className: "host-table", id: "depots-table" });
		const headerRow = createElement("tr");
		["Depot ID", "Description", "OPSI host key", "Is master", "Messagebus", "Transfer slots"].forEach(label => {
			headerRow.appendChild(createElement("th", { className: "host-th" }, [label]));
		});
		table.appendChild(headerRow);
		data.forEach(depot => {
			const connected = depot.configserver || messagebusConnectedDepots.includes(depot.id);
			const cls = "host-" + (connected ? "connected" : "not-connected");
			const row = createElement("tr");
			row.appendChild(createElement("td", { className: "host-td" }, [depot.id]));
			row.appendChild(createElement("td", { className: "host-td" }, [depot.description]));
			row.appendChild(createElement("td", {
				className: "host-td",
				style: { cursor: "pointer", textSecurity: "disc", webkitTextSecurity: "disc" },
				onclick: event => toggleTextSecurityVisibility(event.currentTarget)
			}, [depot.opsiHostKey]));
			row.appendChild(createElement("td", { className: "host-td", style: { textAlign: "center" } }, [
				createElement("input", { type: "checkbox", disabled: true, checked: depot.isMasterDepot })
			]));
			row.appendChild(createElement("td", {
				id: `depot-messagebus-state-${depot.id}`,
				className: `host-td ${cls}`,
				dataset: { depotId: depot.id, configserver: depot.configserver }
			}, [connected ? "connected" : "not connected"]));
			row.appendChild(createElement("td", { className: "host-td" }, [`${depot.used_product_sync_transfer_slots}/${depot.max_product_sync_transfer_slots}`]));
			table.appendChild(row);
		});
		replaceContent(container, [table]);
	}
	return container.innerHTML;
}



function renderRPCCacheInfoTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (Object.keys(data).length === 0) {
		replaceContent(container, [createElement("p", {}, ["RPC cache is empty."])]);
	} else {
		const rows = Object.entries(data).map(([cacheName, numResults]) => ({ cacheName, numResults }));
		const table = createTable("rpc-cache-table", "rpc-cache-th", [
			{ label: "Cache name", cellClassName: "rpc-cache-td", render: row => row.cacheName },
			{ label: "Num results", cellClassName: "rpc-cache-td", render: row => row.numResults },
			{ label: "Clear", cellClassName: "rpc-cache-td", render: row => createElement("button", { onclick: () => clearRPCCache(row.cacheName) }, ["Clear"]) }
		], rows);
		table.id = "rpc-cache-table";
		replaceContent(container, [table]);
	}
	return container.innerHTML;
}

function sortIndicator(active, sortDesc) {
	if (!active) {
		return "";
	}
	return sortDesc ? " \u25BC" : " \u25B2";
}

function renderRPCTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	const table = createElement("table", { className: "rpc-table" });
	const headerRow = createElement("tr");
	const keys = Object.keys(data[0]);
	keys.forEach(key => {
		const active = rpcTableSort.sortBy === key;
		headerRow.appendChild(createElement("th", {
			className: active ? "rpc-th sorted" : "rpc-th",
			title: "sort",
			style: { cursor: "pointer" },
			onclick: () => loadRPCTable(key, active ? !rpcTableSort.sortDesc : true)
		}, [key + sortIndicator(active, rpcTableSort.sortDesc)]));
	});
	table.appendChild(headerRow);

	data.forEach(element => {
		const row = createElement("tr");
		let tdClass = "rpc-td";
		if (element["error"]) {
			tdClass = "rpc-error-td";
		}
		else if (element["deprecated"]) {
			tdClass = "rpc-deprecated-td";
		}
		keys.forEach(key => {
			let value = element[key];
			if (key == "date") {
				value = formatDate(parseUTCDate(element[key]));
			}
			else if (key == "duration") {
				value = element[key].toFixed(4);
			}
			row.appendChild(createElement("td", { className: tdClass }, [value]));
		});
		table.appendChild(row);
	});

	replaceContent(container, [table]);
	return container.innerHTML;
}


function renderAuditLogTable(data, htmlId) {
	const container = document.getElementById(htmlId);
	if (!container) {
		return "";
	}
	if (data == undefined || data.length == 0) {
		container.textContent = "No audit log entries found.";
		return "";
	}

	const columns = [
		"created",
		"eventType",
		"username",
		"clientAddress",
		"userAgent",
		"authMethods",
		"failureReason",
		"logoutReason",
		"productId",
		"clientId",
		"actionRequest",
		"message"
	];
	const table = createElement("table", { className: "audit-log-table" });
	const headerRow = createElement("tr");
	columns.forEach(column => {
		const active = auditLogTableSort.sortBy === column;
		headerRow.appendChild(createElement("th", {
			className: active ? "audit-log-th sorted" : "audit-log-th",
			title: "sort",
			style: { cursor: "pointer" },
			onclick: () => loadAuditLogTable(column, active ? !auditLogTableSort.sortDesc : true)
		}, [column + sortIndicator(active, auditLogTableSort.sortDesc)]));
	});
	table.appendChild(headerRow);
	data.forEach(entry => {
		const row = createElement("tr");
		columns.forEach(column => {
			let value = entry[column];
			if (column == "created" && value) {
				value = formatDate(parseUTCDate(value));
			}
			row.appendChild(createElement("td", { className: "audit-log-td" }, [textOrEmpty(value)]));
		});
		table.appendChild(row);
	});
	replaceContent(container, [table]);
	return container.innerHTML;
}


function outputToHTML(json, id) {
	if (json == undefined) {
		return
	}
	let jsonStr = JSON.stringify(json, undefined, 2);
	jsonStr = syntaxHighlight(jsonStr);
	document.getElementById(id).style.visibility = 'visible'
	document.getElementById(id).innerHTML = jsonStr;
}


function decodeHTML(html) {
	var txt = document.createElement('textarea');
	txt.innerHTML = html;
	return txt.value;
}


// Dates from the API are UTC. Parse them as UTC so formatDate can render them in local time.
function parseUTCDate(value) {
	if (value === undefined || value === null || value === "") {
		return null;
	}
	if (typeof value === "number") {
		return new Date(value * 1000);
	}
	let str = String(value).trim().replace(" ", "T");
	// Append 'Z' if the string has a time component but no timezone information.
	if (str.includes("T") && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(str)) {
		str += "Z";
	}
	return new Date(str);
}


function formatDate(date) {
	let year = date.getFullYear();
	let month = date.getMonth() + 1;
	let dt = date.getDate();
	let hour = date.getHours();
	let minutes = date.getMinutes();
	let seconds = date.getSeconds();

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
	return year + '-' + month + '-' + dt + ' ' + hour + ':' + minutes + ':' + seconds;
}


var messagebusWS;
var messagebusAutoReconnect = true;
var mbTerminal;
const utf8Encoder = new TextEncoder();

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

function getMessagebusChannelInfo() {
	let filter = {};
	document.getElementById('messagebus-channel-info-filter').value.split(",").forEach(element => {
		let keyval = element.split("=", 2);
		if (keyval.length != 2) {
			keyval = ["channel", keyval[0]];
		}
		filter[keyval[0].trim()] = keyval[1].trim();
	});
	let req = ajaxRequest("POST", "/admin/messagebus-channel-info", { "filter": filter });
	req.then((result) => {
		outputToHTML(result, "messagebus-result");
		return result;
	});
}


function messagebusConnect() {
	const serverRole = localStorage.getItem("serverRole") || "configserver";
	if (serverRole != "configserver") {
		showNotification(`Messagebus unavailable on ${serverRole}`, "messagebus", "error", 10);
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
		showNotification("Connected to messagebus", "messagebus", "success", 2);
		document.getElementById("messagebus-connect-disconnect").textContent = "Disconnect";
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
				"event:config_created",
				"event:config_deleted",
				"event:config_updated",
				"event:configState_created",
				"event:configState_deleted",
				"event:configState_updated",
				"event:host_connected",
				"event:host_created",
				"event:host_deleted",
				"event:host_disconnected",
				"event:host_updated",
				"event:productOnClient_created",
				"event:productOnClient_deleted",
				"event:productOnClient_updated",
				"event:user_connected",
				"event:user_disconnected",
			]
		}
		messagebusSend(dataMessage);
	};
	messagebusWS.onclose = function () {
		console.log("Messagebus websocket closed");
		if (messagebusAutoReconnect) {
			showNotification("Messagebus connection lost", "messagebus", "error", 10);
		}
		else {
			showNotification("Messagebus connection closed", "messagebus", "success", 2);
		}
		messagebusWS = null;
		if (messagebusAutoReconnect) {
			setTimeout(messagebusConnect, 5000);
		}
		document.getElementById("messagebus-connect-disconnect").textContent = "Connect";
	};
	messagebusWS.onerror = function (error) {
		const err = `Messagebus websocket connection error: ${JSON.stringify(error)}`;
		console.error(err);
		//showNotification(err, "messagebus", "error", 5);
		messagebusWS = null;
		document.getElementById("messagebus-connect-disconnect").textContent = "Connect";
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
					mbTerminal.writeln("\r\n\x1b[1;37m> Terminal closed <\x1b[0m");
					mbTerminal.write("\x1b[?25l"); // Make cursor invisible
				}
				else if (message.type == "terminal_error") {
					console.error("Terminal error", message);
					let notificationText = message.error.message;
					if (message.error.details) {
						notificationText += "\n" + message.error.details;
					}
					showNotification(notificationText, "", "error", 10);
				}
			}
		}
		else if (message.type == "file_upload_response") {
			messagebusFileUploadReadChunk(message.file_id);
		}
		else if (message.type == "file_upload_result") {
			document.querySelector('#terminal-xterm .xterm-cursor-layer').classList.remove("upload-active");
			let dataMessage = {
				type: "terminal_data_write",
				id: createUUID(),
				sender: "@",
				channel: mbTerminal.terminalChannel,
				created: Date.now(),
				expires: Date.now() + 10000,
				terminal_id: mbTerminal.terminalId,
				data: utf8Encoder.encode('"' + message.path + '"' + ("\x1b[D".repeat(message.path.length + 2)))
			}
			messagebusSend(dataMessage);
			if (fileUploads[message.file_id]) {
				delete fileUploads[message.file_id];
			}
		}
		else if (message.type == "general_error" || message.type == "file_transfer_error") {
			console.error(message.error);
			showNotification(message.error.message + "\n" + message.error.details, "", "error", 10);
			if (message.type == "general_error" || message.type == "file_transfer_error") {
				document.querySelector('#terminal-xterm .xterm-cursor-layer').classList.remove("upload-active");
				if ((message.type == "file_transfer_error") && message.file_id && fileUploads[message.file_id]) {
					delete fileUploads[message.file_id];
				}
			}
		}

		if (
			(!message.type.startsWith("terminal_data") || document.getElementById('messagebus-message-show-terminal-data-messages').checked) &&
			(!message.type.startsWith("file_chunk") || document.getElementById('messagebus-message-show-file-chunk-messages').checked)
		) {
			const maxLength = 1000000;
			let messages = document.getElementById("messagebus-message-in").innerHTML + "<div>" + syntaxHighlightMessage(message) + "</div>";
			if (messages.length > maxLength) {
				let start = messages.indexOf("<div>", messages.length - maxLength);
				if (start > 0) {
					messages = messages.substring(start, messages.length);
				}
			}
			document.getElementById("messagebus-message-in").innerHTML = messages;
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
		showNotification("Messagebus not connected.", "messagebus", "error", 3);
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
		showNotification("Sending expired message", "messagebus", "warning", 5);
	}
	try {
		messagebusWS.send(msgpack.serialize(message));
	}
	catch (error) {
		console.error(error);
		showNotification(error, "messagebus", "error", 10);
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
	let states = document.querySelectorAll('[id^="depot-messagebus-state-"][data-configserver="false"]');
	states.forEach(element => {
		const connected = messagebusConnectedDepots.includes(element.dataset.depotId);
		element.textContent = connected ? 'connected' : 'not connected';
		if (connected) {
			element.classList.remove("host-not-connected");
			element.classList.add("host-connected");
		}
		else {
			element.classList.remove("host-connected");
			element.classList.add("host-not-connected");
		}
	});

	const clients = document.getElementById("messagebus-connected-clients");
	clients.replaceChildren();
	const clientList = document.createElement("ul");
	messagebusConnectedClients.sort();
	messagebusConnectedClients.forEach(clientId => {
		const client = document.createElement("li");
		client.textContent = clientId;
		clientList.appendChild(client);
	});
	clients.appendChild(clientList);
}

function updateMessagebusConnectedUsers() {
	let states = document.querySelectorAll('[id^="user-messagebus-state-"]');
	states.forEach(element => {
		let connected = messagebusConnectedUsers.includes(element.dataset.userId);
		element.textContent = connected ? 'connected' : 'not connected';
		if (connected) {
			element.classList.remove("user-not-connected");
			element.classList.add("user-connected");
		}
		else {
			element.classList.remove("user-connected");
			element.classList.add("user-not-connected");
		}
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
		if (availableModules.includes("vpn")) {
			messagebusConnectedClients.forEach(clientId => {
				option = document.createElement("option");
				option.text = `Client ${clientId}`;
				option.dataset.channel = `host:${clientId}`;
				select.appendChild(option);
			});
		}
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
		showNotification("Messagebus not connected.", "messagebus", "error", 3);
		return;
	}
	let terminalChannel = document.getElementById("terminal-channel").value;
	if (!terminalChannel) {
		showNotification("Invalid channel.", "messagebus", "error", 3);
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
			let message = {
				type: "terminal_data_write",
				id: createUUID(),
				sender: "@",
				channel: mbTerminal.terminalChannel,
				created: Date.now(),
				expires: Date.now() + 10000,
				terminal_id: mbTerminal.terminalId,
				data: utf8Encoder.encode(data)
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

let fileUploads = {};

function messagebusFileUploadReadChunk(fileId) {
	let fu = fileUploads[fileId];
	if (!fu) {
		console.error("File upload not found", fileId);
		return;
	}
	let blob = fu["file"].slice(fu["offset"], fu["offset"] + fu["chunkSize"]);
	fu["offset"] += fu["chunkSize"];
	fileUploads[fileId]["chunk"] += 1;
	fu["reader"].readAsArrayBuffer(blob);
}

function messagebusFileUpload(file, channel, terminalId = null) {
	let fileId = createUUID();
	var reader = new FileReader();

	reader.onload = function () {
		const last = (fileUploads[fileId]["offset"] >= file.size);

		let message = {
			type: "file_chunk",
			id: createUUID(),
			sender: "@",
			channel: channel,
			created: Date.now(),
			expires: Date.now() + 10000,
			file_id: fileId,
			number: fileUploads[fileId]["chunk"],
			data: new Uint8Array(reader.result),
			last: last
		}
		messagebusSend(message);
		if (!last) {
			// Do not send the next chunk immediately
			// to keep some resources for further messages
			setTimeout(function () {
				messagebusFileUploadReadChunk(fileId);
			}, 5);
		}
	}
	fileUploads[fileId] = {
		"chunk": 0, "offset": 0, "chunkSize": 10000, "file": file, "reader": reader
	};

	console.log("messagebusFileUpload:", file, channel);
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
			if (term) {
				setTimeout(function () {
					term.fitAddon.fit();
				}, 250);
			}
		});
		elem.setAttribute('fullscreenchangelistener', 'true');
	}

	if (elem.requestFullscreen) {
		elem.requestFullscreen();
	}
}


function stopTerminal() {
	if (!mbTerminal) return;

	const message = {
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


function generateLicensingInfoTable(info, htmlId) {
	const table = createElement("table", { id: "licensing-info-table" });
	for (const [key, val] of Object.entries(info)) {
		table.appendChild(createElement("tr", {}, [
			createElement("td", { className: "licensing-info-key" }, [key]),
			createElement("td", {}, [val])
		]));
	}
	replaceContent(htmlId, [table]);
}


function generateLicensingDatesTable(dates, activeDate, htmlId) {
	const table = createElement("table", { id: "licensing-dates-table" });
	const headerRow = createElement("tr", {}, [createElement("th", {}, ["Module"])]);
	for (const date of Object.keys(Object.values(dates)[0])) {
		headerRow.appendChild(createElement("th", {}, [date]));
	}
	table.appendChild(headerRow);
	for (const [moduleId, dateData] of Object.entries(dates)) {
		const row = createElement("tr", {}, [createElement("td", {}, [moduleId])]);
		for (const [date, moduleData] of Object.entries(dateData)) {
			let title = "";
			for (const [k, v] of Object.entries(moduleData)) {
				title += `${k}: ${v}\n`;
			}
			const changed = moduleData['changed'] ? 'changed' : '';
			const active = date == activeDate ? 'active' : 'inactive';
			const text = moduleData['client_number'] == 999999999 ? 'unlimited' : moduleData['client_number'];
			row.appendChild(createElement("td", { title: title, className: `${changed} ${moduleData['state']} ${active}` }, [text]));
		}
		table.appendChild(row);
	}
	replaceContent(htmlId, [table]);
}


function toggleTabMaximize() {
	const tabcontent = document.getElementsByClassName("tabcontent");
	let buttonText = "Maximize";
	for (let i = 0; i < tabcontent.length; i++) {
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
	const buttons = document.getElementsByClassName("tab-maximize");
	for (let i = 0; i < buttons.length; i++) {
		buttons[i].textContent = buttonText;
	}
	if (mbTerminal) mbTerminal.fitAddon.fit();
}


document.onkeydown = function (evt) {
	evt = evt || window.event;
	if (evt.ctrlKey && evt.key == "F11") {
		toggleTabMaximize();
	}
};

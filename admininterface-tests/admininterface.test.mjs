import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { JSDOM } from "jsdom";

function loadAdmininterface() {
	const dom = new JSDOM(`<!DOCTYPE html><html><body>
		<div id="notifications"></div>
		<div id="confirm-overlay" class="overlay-backdrop">
			<h4 id="confirm-overlay-title"></h4>
			<p id="confirm-overlay-message"></p>
			<div id="confirm-overlay-body"></div>
			<button id="confirm-overlay-cancel"></button>
			<button id="confirm-overlay-confirm"></button>
		</div>
		<div id="user-table-div"></div>
		<div id="depots-table-div"></div>
		<div id="rpc-cache-info-div"></div>
		<div id="audit-log-table-div"></div>
	</body></html>`, {
		runScripts: "outside-only",
		url: "https://example.test/admin"
	});
	dom.window.console = console;
	dom.window.ResizeObserver = class ResizeObserver {
		observe() { }
		unobserve() { }
		disconnect() { }
	};
	dom.window.__ajaxRequests = [];
	dom.window.eval(`
		var multiFactorAuth = "inactive";
		var databaseAuth = false;
		var messagebusConnectedUsers = [];
		var messagebusConnectedDepots = [];
		var messagebusConnectedClients = [];
		var ajaxRequest = (...args) => {
			window.__ajaxRequests.push(args);
			return new Promise(() => {});
		};
	`);
	dom.window.eval(`${readFileSync("../opsiconfd_data/static/javascript/admininterface.js", "utf8")}
		Object.assign(window, {
			renderUserTable,
			showDialogOverlay,
			renderDepotTable,
			renderRPCCacheInfoTable,
			renderAuditLogTable,
			setMessagebusConnectedDepots: value => { messagebusConnectedDepots = value; }
		});
	`);
	return dom;
}

test("renderUserTable renders text safely and keeps actions callable", () => {
	const dom = loadAdmininterface();
	const { window } = dom;
	window.multiFactorAuth = "totp_optional";
	window.databaseAuth = true;
	window.messagebusConnectedUsers = ["admin"];

	window.renderUserTable([
		{
			id: "evil <img src=x onerror=alert(1)>",
			groups: ["opsiadmin<script>bad()</script>"],
			lastLogin: null,
			internal_auth: true,
			token_auth: false,
			mfaState: "inactive"
		}
	], "user-table-div");

	const container = window.document.getElementById("user-table-div");
	assert.match(container.textContent, /evil <img src=x onerror=alert\(1\)>/);
	assert.equal(container.querySelectorAll("img").length, 0);
	assert.equal(container.querySelectorAll("script").length, 0);
	assert.equal(container.querySelector(".action-menu-button").textContent, "Actions");
});

test("showDialogOverlay displays message and safely accepts DOM body", () => {
	const dom = loadAdmininterface();
	const { window } = dom;
	const body = window.document.createElement("strong");
	body.textContent = "Safe body";

	window.showDialogOverlay({
		title: "Delete user?",
		message: "This action cannot be undone.",
		bodyElement: body,
		confirmLabel: "Delete",
		cancelLabel: "Cancel"
	});

	assert.equal(window.document.getElementById("confirm-overlay-title").textContent, "Delete user?");
	assert.equal(window.document.getElementById("confirm-overlay-message").textContent, "This action cannot be undone.");
	assert.equal(window.document.getElementById("confirm-overlay-body").textContent, "Safe body");
	assert.equal(window.document.getElementById("confirm-overlay").classList.contains("active"), true);
});

test("renderDepotTable masks host key and updates text without HTML injection", () => {
	const dom = loadAdmininterface();
	const { window } = dom;
	window.setMessagebusConnectedDepots(["depot1.example.test"]);

	window.renderDepotTable([
		{
			id: "depot1.example.test",
			description: "Depot <b>one</b>",
			opsiHostKey: "secret<key>",
			isMasterDepot: true,
			configserver: false,
			used_product_sync_transfer_slots: 1,
			max_product_sync_transfer_slots: 3
		}
	], "depots-table-div");

	const container = window.document.getElementById("depots-table-div");
	assert.match(container.textContent, /Depot <b>one<\/b>/);
	assert.equal(container.querySelectorAll("b").length, 0);
	assert.equal(window.document.getElementById("depot-messagebus-state-depot1.example.test").textContent, "connected");
});

test("renderRPCCacheInfoTable wires clear callback without inline JavaScript", () => {
	const dom = loadAdmininterface();
	const { window } = dom;

	window.renderRPCCacheInfoTable({ "cache'name<script>": 2 }, "rpc-cache-info-div");
	const button = window.document.querySelector("#rpc-cache-info-div button");
	button.click();

	assert.equal(window.__ajaxRequests[0][0], "POST");
	assert.equal(window.__ajaxRequests[0][1], "/redis-interface/clear-rpc-cache");
	assert.equal(window.__ajaxRequests[0][2].cache_name, "cache'name<script>");
	assert.equal(button.getAttribute("onclick"), null);
	assert.equal(window.document.querySelectorAll("script").length, 0);
});

test("renderAuditLogTable renders values as text", () => {
	const dom = loadAdmininterface();
	const { window } = dom;
	window.renderAuditLogTable([
		{ created: "now", eventType: "login", username: "<admin>", message: "<img src=x>" }
	], "audit-log-table-div");

	const container = window.document.getElementById("audit-log-table-div");
	assert.match(container.textContent, /<admin>/);
	assert.match(container.textContent, /<img src=x>/);
	assert.equal(container.querySelectorAll("img").length, 0);
});


// import { msgpack } from "./msgpack.js"
// msgpack = require('msgpack');
var MAX_LOG_LINES = 5000;
var ws;
var contextFilterRegex = null;
var messageFilterRegex = null;
var levelFilter = 9;
var logLineId = 0;
var collapsed = true;
var autoScroll = true;
var autoReconnect = true;
var reconnectTimer = null;

function addRecordToLog(record) {
	logLineId++;

	//console.log(record)
	let date = new Date(record.created * 1000);
	let day = String(date.getDate()).padStart(2, "0");
	let month = String(date.getMonth() + 1).padStart(2, "0");
	let year = String(date.getFullYear());
	let hour = String(date.getHours()).padStart(2, "0");
	let minute = String(date.getMinutes()).padStart(2, "0");
	let second = String(date.getSeconds()).padStart(2, "0");
	let msec = String(date.getMilliseconds()).padStart(3, "0");
	let time = year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second + ',' + msec;

	let div = document.createElement('div');
	div.setAttribute("class", "log-line");
	div.setAttribute("id", "log-line-" + logLineId);

	let context = "";
	if (record.context) {
		for (key in record.context) {
			if (key != "logger") {
				if (context != "") context = context + ",";
				context = context + record.context[key];
			}
		}
	}

	let msg = record.msg + "\n";
	if (record.exc_text) {
		msg += "\n" + record.exc_text;
	}
	let idx = msg.indexOf('\n');
	if (idx > -1) {
		idx = msg.indexOf('\n', idx + 1);
		if (idx > -1) {
			if (collapsed) {
				div.classList.add("log-line-multiline-collapsed");
			}
			else {
				div.classList.add("log-line-multiline");
			}
		}
	}

	let elControl = document.createElement('div');
	elControl.classList.add("log-record-control");

	let elCollapse = document.createElement('span');
	elCollapse.classList.add("log-record-collapse");
	elCollapse.onclick = toggleCollapse;

	let elLineId = document.createElement('span');
	elLineId.classList.add("log-record-line-id");
	elLineId.appendChild(document.createTextNode(logLineId));

	elControl.appendChild(elCollapse);
	elControl.appendChild(elLineId);

	let elRecord = document.createElement('div');
	elRecord.classList.add("log-record");

	let elOpsiLevel = document.createElement('span');
	elOpsiLevel.classList.add("log-record-opsilevel");
	elOpsiLevel.classList.add("LEVEL_" + record.levelname);
	elOpsiLevel.appendChild(document.createTextNode("[" + record.opsilevel + "] "));

	let elDate = document.createElement('span');
	elDate.classList.add("log-record-date");
	elDate.classList.add("LEVEL_" + record.levelname);
	elDate.appendChild(document.createTextNode("[" + time + "] "));

	let elContext = document.createElement('span');
	elContext.classList.add("log-record-context");
	elContext.appendChild(document.createTextNode("[" + context.padEnd(16, ' ') + "] "));

	let elMessage = document.createElement('span');
	elMessage.classList.add("log-record-message");
	elMessage.appendChild(document.createTextNode(msg));

	elRecord.appendChild(elOpsiLevel);
	elRecord.appendChild(elDate);
	elRecord.appendChild(elContext);
	elRecord.appendChild(elMessage);

	div.appendChild(elControl);
	div.appendChild(elRecord);

	if (levelFilter && record.opsilevel > levelFilter) {
		div.classList.add("log-line-hidden");
	}
	else if (contextFilterRegex && (!elContext.innerText.match(contextFilterRegex))) {
		div.classList.add("log-line-hidden");
	}
	else if (messageFilterRegex && (!elMessage.innerText.match(messageFilterRegex))) {
		div.classList.add("log-line-hidden");
	}

	let container = document.getElementById("log-line-container");
	if (container.childElementCount >= MAX_LOG_LINES) {
		container.removeChild(container.childNodes[0]);
	}
	container.appendChild(div);
	return div;
}

function toggleCollapse() {
	let el = this.parentElement.parentElement;
	if (el.classList.contains("log-line-multiline")) {
		el.classList.remove("log-line-multiline");
		el.classList.add("log-line-multiline-collapsed");
	}
	else {
		el.classList.remove("log-line-multiline-collapsed");
		el.classList.add("log-line-multiline");
	}
}

function collapseAll(col) {
	collapsed = col;
	let container = document.getElementById("log-container");
	if (collapsed) {
		container.querySelectorAll(".log-line-multiline").forEach(function (el) {
			el.classList.remove("log-line-multiline");
			el.classList.add("log-line-multiline-collapsed");
		});
	}
	else {
		container.querySelectorAll(".log-line-multiline-collapsed").forEach(function (el) {
			el.classList.remove("log-line-multiline-collapsed");
			el.classList.add("log-line-multiline");
		});
	}
}

function setAutoScroll(auto) {
	if (auto != autoScroll) {
		autoScroll = auto;
		document.getElementById("auto-scroll").checked = autoScroll;
		let container = document.getElementById("log-line-container");
		let element = container.lastChild;
		if (element) {
			element.scrollIntoView({ block: "end", behavior: "smooth" });
		}
	}
}

function applyContextFilter(filter = null) {
	if (filter) {
		contextFilterRegex = new RegExp(filter, 'i');
	}
	else {
		contextFilterRegex = null;
	}
	applyFilter();
}

function applyMessageFilter(filter = null) {
	if (filter) {
		messageFilterRegex = new RegExp(filter, 'i');
	}
	else {
		messageFilterRegex = null;
	}
	applyFilter();
}

function applyLevelFilter(filter = null) {
	if (filter) {
		levelFilter = parseInt(filter);
		if (levelFilter < 1) levelFilter = 1;
		else if (levelFilter > 9) levelFilter = 9;
	}
	else {
		levelFilter = null;
	}
	applyFilter();
}

function applyFilter() {
	let container = document.getElementById("log-line-container");
	let filteredIds = [];
	if (levelFilter && levelFilter < 9) {
		container.querySelectorAll(".log-record-opsilevel").forEach(function (el) {
			if (parseInt(el.innerText.replace(/\D/g, '')) > levelFilter && !filteredIds.includes(el.parentElement.parentElement.id)) {
				filteredIds.push(el.parentElement.parentElement.id);
			}
		});
	}
	if (contextFilterRegex) {
		container.querySelectorAll(".log-record-context").forEach(function (el) {
			if (!el.innerText.match(contextFilterRegex) && !filteredIds.includes(el.parentElement.parentElement.id)) {
				filteredIds.push(el.parentElement.parentElement.id);
			}
		});
	}
	if (messageFilterRegex) {
		container.querySelectorAll(".log-record-message").forEach(function (el) {
			if (!el.innerText.match(messageFilterRegex) && !filteredIds.includes(el.parentElement.parentElement.id)) {
				filteredIds.push(el.parentElement.parentElement.id);
			}
		});
	}

	container.querySelectorAll(".log-line").forEach(function (el) {
		if (filteredIds.includes(el.id)) {
			el.classList.add("log-line-hidden");
		}
		else {
			el.classList.remove("log-line-hidden");
		}
	});
}

function setMessage(text = "", className = "LEVEL_INFO") {
	let con = document.getElementById("log-msg-container");
	if (text) {
		con.innerHTML = text;
		con.style.visibility = "visible";
	}
	else {
		con.innerHTML = "";
		con.style.visibility = "hidden";
	}
	con.className = className;
}

function startLog() {
	stopLog();
	startTime = Math.round(Date.now() / 1000) - 300; // last 5 minutes

	setMessage("Connecting...");
	if (reconnectTimer) {
		clearTimeout(reconnectTimer);
		reconnectTimer = null;
	}
	logLineId = 0;
	var client = null;
	var params = []
	if (startTime) {
		params.push("start_time=" + startTime);
	}
	if (client) {
		params.push("client=" + client);
	}

	var loc = window.location;
	var ws_uri;
	if (loc.protocol == "https:") {
		ws_uri = "wss:";
	} else {
		ws_uri = "ws:";
	}
	ws_uri += "//" + loc.host;
	ws = new WebSocket(ws_uri + "/ws/log_viewer?" + params.join('&'));
	ws.binaryType = 'arraybuffer';

	ws.onopen = function () {
		// websocket is connected
		document.getElementById("log-line-container").innerHTML = "";
		setMessage("");
		//ws.send(msg);
	};

	ws.onmessage = function (event) {
		var message = msgpack.deserialize(event.data, true);
		//console.log(message);
		if (message[0].type == "log-records") {
			let element;
			if (message.payload) {
				for (let i = 0; i < message.payload.length; i++) {
					element = addRecordToLog(message.payload[i]);
				}
			}
			if (message.length > 1) {
				for (let i = 1; i < message.length; i++) {
					element = addRecordToLog(message[i]);
				}
			}
			if (autoScroll && element) {
				element.scrollIntoView({ block: "end", behavior: "smooth" });
			}
		}
	};

	ws.onclose = function (event) {
		// websocket is closed.
		console.log("Websocket conection closed");
		if (event.code == 1000) {
			return;
		}
		let msg = "Connection lost";
		if (event.reason) {
			msg = msg + ": " + event.reason;
		}
		setMessage(msg, "LEVEL_ERROR");
		if (autoReconnect) {
			reconnectTimer = setTimeout(startLog, 5000);
		}
	};
}

function changeFontSize(val) {
	var cont = document.getElementById("log-line-container");
	var size = parseInt(cont.style.fontSize.replace(/\D/g, ''));
	size += val;
	if (size < 1) { size = 1; }
	cont.style.fontSize = String(size) + "px";
}

function stopLog() {
	if (ws != undefined) {
		console.log("Closing websocket");
		ws.close(1000, "LogViewer closed.")
	}
}
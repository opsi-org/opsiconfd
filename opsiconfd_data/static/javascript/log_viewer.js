
// import { msgpack } from "./msgpack.js"
// msgpack = require('msgpack');
var MAX_LOG_LINES = 5000;
var ws;
var contextFilterRegex = null;
var messageFilterRegex = null;
var levelFilter = 9;
var logLineId = 0;

function addRecordToLog(record) {
	logLineId++;

	//console.log(record)
	let date = new Date((record.created - (new Date()).getTimezoneOffset() * 60) * 1000);	
	let day = String(date.getDay()).padStart(2, "0");
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
			if (context != "") context = context + ",";
			context = context + record.context[key];
		}
	}
	
	let msg = record.msg + "\n";
	if (record.exc_text) {
		msg += "\n" + record.exc_text;
	}

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
	
	div.appendChild(elOpsiLevel);
	div.appendChild(elDate);
	div.appendChild(elContext);
	div.appendChild(elMessage);
	if (levelFilter && record.opsilevel > levelFilter) {
		div.classList.add("log-line-hidden");
	}
	else if (contextFilterRegex && (!elContext.innerText.match(contextFilterRegex))) {
		div.classList.add("log-line-hidden");
	}
	else if (messageFilterRegex && (!elMessage.innerText.match(messageFilterRegex))) {
		div.classList.add("log-line-hidden");
	}

	let container = document.getElementById("log-container");
	if (container.childElementCount >= MAX_LOG_LINES) {
		container.removeChild(container.childNodes[0]); 
	}
	container.appendChild(div);
	return div;
}

function applyContextFilter(filter=null) {
	if (filter) {
		contextFilterRegex = new RegExp(filter, 'i');
	}
	else {
		contextFilterRegex = null;	startLog();
	}
	applyFilter();
}

function applyMessageFilter(filter=null) {
	if (filter) {
		messageFilterRegex = new RegExp(filter, 'i');
	}
	else {
		messageFilterRegex = null;
	}
	applyFilter();
}

function applyLevelFilter(filter=null) {
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
	let container = document.getElementById("log-container");
	let filteredIds = [];
	if (levelFilter && levelFilter < 9) {
		container.querySelectorAll(".log-record-opsilevel").forEach(function(el) {
			if (parseInt(el.innerText.replace(/\D/g, '')) > levelFilter && !filteredIds.includes(el.parentElement.id)) {
				filteredIds.push(el.parentElement.id);
			}
		});
	}
	if (contextFilterRegex) {
		container.querySelectorAll(".log-record-context").forEach(function(el) {
			if (!el.innerText.match(contextFilterRegex) && !filteredIds.includes(el.parentElement.id)) {
				filteredIds.push(el.parentElement.id);
			}
		});
	}
	if (messageFilterRegex) {
		container.querySelectorAll(".log-record-message").forEach(function(el) {
			if (!el.innerText.match(messageFilterRegex) && !filteredIds.includes(el.parentElement.id)) {
				filteredIds.push(el.parentElement.id);
			}		
		});
	}
	
	container.querySelectorAll(".log-line").forEach(function(el) {
		if (filteredIds.includes(el.id)) {
			el.classList.add("log-line-hidden");
		}
		else {
			el.classList.remove("log-line-hidden");
		}
	});
}

function startLog() {
	var start_time = Math.round(Date.now()-10000); // millseconds
	var client = null;
	var params = []
	if (start_time) {
		params.push("start_time=" + start_time);
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

	ws.onopen = function() {
		// websocket is connected
		document.getElementById("log-container").innerHTML = '';
		//ws.send(msg);
	};
	
	ws.onmessage = function (message) {
		//console.log(message.data);
		message.data.arrayBuffer().then(function(buffer) {
			let container = document.getElementById("log-container");
			let scrollToBottom = (container.scrollHeight - container.scrollTop === container.clientHeight);
			buffer = new Uint8Array(buffer, 0);
			var records = msgpack.deserialize(buffer, true);
			var element;
			for (let i=0; i<records.length; i++) {
				element = addRecordToLog(records[i]);
			}
			if (scrollToBottom && element) {
				element.scrollIntoView({block: "end", behavior: "auto"});
			}
		});
		
	};
	
	ws.onclose = function(event) {
		// websocket is closed.
		console.log("Websocket conection closed");
		if (event.code == 4401) {
			document.getElementById("log-container").innerHTML =
				`<div class="LEVEL_ERROR" style="margin: 10px; font-size: 20px">${event.reason}</div>`;
		}
	};
}

function change_font_size(val) {
	var cont = document.getElementById("log-container");
	var size = parseInt(cont.style.fontSize.replace(/\D/g, ''));
	size += val;
	if (size < 1) { size = 1; }
	cont.style.fontSize = String(size) + "px";
}

function stopLog(){
	if(ws != undefined){
		ws.close(1000, "LogViewer closed.")
	}	
}
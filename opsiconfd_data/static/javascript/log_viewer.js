
// import { msgpack } from "./msgpack.js"
// msgpack = require('msgpack');
var MAX_LOG_LINES = 5000;
var ws;

function addRecordToLog(record) {
	//console.log(record)
	var date = new Date((record.created - (new Date()).getTimezoneOffset() * 60) * 1000);	
	var day = String(date.getDay()).padStart(2, "0");
	var month = String(date.getMonth() + 1).padStart(2, "0");
	var year = String(date.getFullYear());
	var hour = String(date.getHours()).padStart(2, "0");
	var minute = String(date.getMinutes()).padStart(2, "0");
	var second = String(date.getSeconds()).padStart(2, "0");
	var msec = String(date.getMilliseconds()).padStart(3, "0");
	var time = year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second + ',' + msec;

	var div = document.createElement('div');
	div.setAttribute("class", "log-line");

	var colorSpan = document.createElement('span');
	colorSpan.setAttribute("class", "LEVEL_" + record.levelname);
	
	var context = "";
	if (record.context) {
		for (key in record.context) {
			if (context != "") context = context + ",";
			context = context + record.context[key];
		}
	}
	var colorText = document.createTextNode("[" + record.opsilevel + "] [" + time + "] [" + context.padEnd(16, ' ') + "]");
	colorSpan.appendChild(colorText);

	div.appendChild(colorSpan);

	var msg = record.msg + "\n";
	if (record.exc_text) {
		msg += "\n" + record.exc_text;
	}
	div.appendChild(document.createTextNode(" " + msg));

	var container = document.getElementById("log-container");
	if (container.childElementCount >= MAX_LOG_LINES) {
		container.removeChild(container.childNodes[0]); 
	}
	container.appendChild(div);
	container.scrollTop = container.scrollHeight;
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
			buffer = new Uint8Array(buffer, 0);
			var records = msgpack.deserialize(buffer, true);
			for (let i=0; i<records.length; i++) {
				addRecordToLog(records[i]);
			}
		});
	};
	
	ws.onclose = function() {
		// websocket is closed.
		console.log("Websocket conection closed");
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
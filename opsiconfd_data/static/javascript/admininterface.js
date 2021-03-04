function unblockAll() {
	let request = new XMLHttpRequest();
	request.open("POST", "/admin/unblock-all");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText
			result = JSON.parse(result);
			outputToHTML(result, "json-result");
			outputResult(result, "text-result");
			loadClientTable()
			return result;

		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send();
}

function unblockClient(ip) {
	let request = new XMLHttpRequest();
	request.open("POST", "/admin/unblock-client");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText
			result = JSON.parse(result);
			outputToHTML(result, "json-result");
			outputResult(result, "text-result");
			loadClientTable();
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	body = {
		"client_addr": ip
	}
	if (ValidateIPaddress(ip)) {
		request.send(JSON.stringify(body));
	}
}

function deleteClientSessions() {
	let request = new XMLHttpRequest();
	request.open("POST", "/admin/delete-client-sessions");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText
			result = JSON.parse(result);
			outputToHTML(result, "json-result");
			outputResult(result, "text-result");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	body = {
		"client_addr": sessionAddr.value
	};
	if (ValidateIPaddress(sessionAddr.value)) {
		request.send(JSON.stringify(body));
	}

}

function outputResult(json, id) {
	let text = "";
	if (json["status"] == 200) {
		data = json["data"]
		let failedCount = 0;
		let blockedCount = 0;
		if(data["redis-keys"] != undefined){
			data["redis-keys"].forEach(element => {
				// console.log(element);
				if(element.includes("failed_auth")){
					failedCount += 1;
				}
				else{
					blockedCount += 1;
				}
			});
		}
		if (data["clients"] != undefined && data["clients"].length != 0) {
			if (blockedCount == 0){
				text = "No blocked clients found."
			}
			else if (blockedCount == 1) {
				text = blockedCount + " client unblocked.";
			} else {
				text = blockedCount + " clients unblocked.";
			}
			if (failedCount == 1) {
				text = text + " Failed logins for "+ failedCount +" client deleted.";
			} else {
				text = text + " Failed logins for "+ failedCount +" clients deleted.";
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

function clearRedisCache(depots =  []) {
	let request = new XMLHttpRequest();
	request.open("POST", "/redis-interface/clear-product-cache");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText
			result = JSON.parse(result);
			outputToHTML(result, "redis-result");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	body = {
		"depots": depots
	};

	request.send(JSON.stringify(body));

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
	alert("You have entered an invalid IP address!")
	return (false)
}

function loadClientTable() {
	let request = new XMLHttpRequest();
	request.open("GET", "/admin/blocked-clients");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			printClientTable(result, "blocked-clients-div");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function loadRPCTable(sortKey, sort) {
	let request = new XMLHttpRequest();
	request.open("GET", "/admin/rpc-list");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			if (result.length == 0) {
				return null
			}
			if (sort) {
				result = sortRPCTable(result, sortKey);
			}
			printRPCTable(result, "rpc-table-div");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send();
	let request_count = new XMLHttpRequest();
	request_count.open("GET", "/admin/rpc-count");
	request_count.addEventListener('load', function (event) {
		if (request_count.status >= 200 && request_count.status < 300) {
			result = request_count.responseText;
			result = JSON.parse(result);
			date = new Date(result["date_first_rpc"])
			// printRPCCount(result["rpc_count"], date)
			return result;
		} else {
			console.warn(request_count.statusText, request_count.responseText);
			return request_count.statusText;
		}
	});
	request_count.send();
}


function loadRedisInfo() {
	let request = new XMLHttpRequest();
	request.open("GET", "/redis-interface/redis-stats");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result, "redis-result");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function loadConfdConfig() {
	let request = new XMLHttpRequest();
	request.open("GET", "/admin/config");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "config-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function objgraphSnapshot(update=false) {
	let max_obj_types = parseInt(document.getElementById("input-objgraph-max-obj-types").value);
	let max_obj = parseInt(document.getElementById("input-objgraph-max-obj").value);

	document.getElementById("button-objgraph-snapshot-new").disabled = true;
	document.getElementById("button-objgraph-snapshot-update").disabled = true;
	let request = new XMLHttpRequest();
	if (update) {
		request.open("GET", "/admin/memory/objgraph-snapshot-update");
	}
	else {
		request.open("GET", `/admin/memory/objgraph-snapshot-new?max_obj_types=${max_obj_types}&max_obj=${max_obj}`);
	}
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			document.getElementById("button-objgraph-snapshot-new").disabled = false;
			document.getElementById("button-objgraph-snapshot-update").disabled = false;
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			document.getElementById("button-objgraph-snapshot-new").disabled = false;
			document.getElementById("button-objgraph-snapshot-update").disabled = false;
			return request.statusText;
		}
	});
	request.send()
}

function objgraphShowBackrefs() {
	let obj_id = document.getElementById("input-objgraph-obj-id").value;
	let win = window.open("/admin/memory/objgraph-show-backrefs?obj_id=" + obj_id, '_blank');
	win.focus();
}

function loadMemoryInfo() {
	let request = new XMLHttpRequest();
	request.open("GET", "/admin/memory-summary");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function takeMemorySnapshot() {
	document.getElementById("memory-info").style.visibility = 'visible';
	document.getElementById("memory-values").innerHTML = "loading...";
	let request = new XMLHttpRequest();
	request.open("POST", "/admin/memory/snapshot");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function diffMemorySnapshots() {
	document.getElementById("memory-info").style.visibility = 'visible';
	document.getElementById("memory-values").innerHTML = "loading...";
	let request = new XMLHttpRequest();

	snapshotNumber1 = document.getElementById("snapshot1").value;
	snapshotNumber2 = document.getElementById("snapshot2").value;
	if (snapshotNumber1 == ""){
		snapshotNumber1 = 1
	}
	if (snapshotNumber2 == ""){
		snapshotNumber2 = -1
	}
	url = "/admin/memory/diff?snapshot1="+snapshotNumber1+"&snapshot2="+snapshotNumber2
	request.open("GET", url);
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function takeHeapSnapshot() {
	document.getElementById("memory-info").style.visibility = 'visible';
	document.getElementById("memory-values").innerHTML = "loading...";
	let request = new XMLHttpRequest();
	request.open("POST", "/admin/memory/guppy");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function diffHeapSnapshots() {
	document.getElementById("memory-info").style.visibility = 'visible';
	document.getElementById("memory-values").innerHTML = "loading...";
	let request = new XMLHttpRequest();

	snapshotNumber1 = document.getElementById("snapshot1").value;
	snapshotNumber2 = document.getElementById("snapshot2").value;
	if (snapshotNumber1 == ""){
		snapshotNumber1 = 1
	}
	if (snapshotNumber2 == ""){
		snapshotNumber2 = -1
	}
	url = "/admin/memory/guppy/diff?snapshot1="+snapshotNumber1+"&snapshot2="+snapshotNumber2
	request.open("GET", url);
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function takeClassSnapshot() {
	document.getElementById("memory-info").style.visibility = 'visible';
	document.getElementById("memory-values").innerHTML = "loading...";
	let request = new XMLHttpRequest();
	request.open("POST", "/admin/memory/classtracker");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	className = document.getElementById("class-name").value;
	moduleName = document.getElementById("module-name").value;
	description = document.getElementById("description").value;
	body = {
		"module": moduleName,
		"class": className,
		"description": description
	}
	request.send(JSON.stringify(body));
}

function classSummary() {
	document.getElementById("memory-info").style.visibility = 'visible';
	document.getElementById("memory-values").innerHTML = "loading...";
	let request = new XMLHttpRequest();
	request.open("GET", "/admin/memory/classtracker/summary");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function deleteMemorySnapshots() {
	let request = new XMLHttpRequest();
	request.open("DELETE", "/admin/memory/snapshot");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function deleteHeapSnapshots() {
	let request = new XMLHttpRequest();
	request.open("DELETE", "/admin/memory/guppy");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function deleteClassTracker() {
	let request = new XMLHttpRequest();
	request.open("DELETE", "/admin/memory/classtracker");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result.data, "memory-values");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send()
}

function printClientTable(data, htmlId) {
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

function printRPCTable(data, htmlId) {
	let htmlStr = "<table class=\"rpc-table\">";
	htmlStr += "<tr>";
	keys = Object.keys(data[0]);
	Object.keys(data[0]).forEach(element => {
		htmlStr += "<th class=\"rpc-th\" onclick=\"loadRPCTable('" + element + "', " + true + ")\" onmouseover=\"\" style=\"cursor: pointer;\">" + element + "</th>";
	});
	htmlStr += "</tr>";

	data.forEach((element, idx) => {
		htmlStr += "<tr>";
		if (element["error"]) {
			keys.forEach(key => {
				htmlStr += "<td class=\"rpc-error-td\">" + element[key] + "</td>";
			});
		} else {
			keys.forEach(key => {
				if(key == "date"){
					date = formateDate(new Date(element[key]))
					htmlStr += "<td class=\"rpc-td\">" + date + "</td>";
				}
				else if(key == "duration"){
					duration = element[key].toFixed(4)
					htmlStr += "<td class=\"rpc-td\">" + duration + "</td>";
				}
				else {
					htmlStr += "<td class=\"rpc-td\">" + element[key] + "</td>";
				}
			});
		}
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
		} else if (sortKey == "date"){
			var dateA = new Date(a[sortKey])
			var dateB = new Date(b[sortKey])
			if (dateA < dateB) {
				return -1;
			}
			if (dateA > dateB) {
				return 1;
			}
			return 0;
		} else if (sortKey == "client"){
			var numA = Number(a[sortKey].split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
			var numB = Number(b[sortKey].split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
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

function callRedis() {
	let request = new XMLHttpRequest();
	request.open("POST", "/redis-interface");
	request.addEventListener('load', function (event) {
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText;
			result = JSON.parse(result);
			outputToHTML(result, "redis-result");
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	cmd = document.getElementById("redis-cmd").value;
	body = {
		"cmd": cmd
	}
	request.send(JSON.stringify(body));
}

function createRequestJSON() {
	let apiJSON = {
		"id": 1,
		"method": "",
		"params": []
	}

	let option = document.getElementById("method-select");
	let method = option.options[option.selectedIndex].text;
	let inputs = document.getElementById("rpcInterface").getElementsByTagName("input");
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
	let inputs = document.getElementById("rpcInterface").getElementsByTagName("input");
	for (i = 0; i < inputs.length; i++) {
		let name = inputs[i].name.trim();
		let value = inputs[i].value.trim();

		if (!value && name.substr(0, 1) != "*") {

			alert("mandatory field empty");
			return {
				"error": "mandatory field empty"
			};
		}
	}

	let apiJSON = createRequestJSON();
	// console.log("apiJSON: ");
	// console.log(apiJSON);
	// console.log(window.location.protocol);
	// console.log(window.location.host);
	// console.log(window.location.hostname);
	// console.log(window.location.port);
	let request = new XMLHttpRequest();
	request.open("POST", "/rpc");

	request.addEventListener('load', function (event) {
		document.getElementById("jsonrpc-execute-button").disabled = false;
		if (request.status >= 200 && request.status < 300) {
			result = request.responseText
			result = JSON.parse(result);
			outputToHTML(result, "jsonrpc-result");
			return result;

		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	document.getElementById("jsonrpc-execute-button").disabled = true;
	request.send(JSON.stringify(apiJSON));
}

function outputToHTML(json, id) {
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

function formateDate(date){
	year = date.getFullYear();
	month = date.getMonth()+1;
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
	if (hour < 10){
		hour = '0' + hour;
	}
	if(minutes < 10){
		minutes = '0' + minutes;
	}
	if (seconds < 10){
		seconds = '0' + seconds;
	}
	date = year+'-' + month + '-'+dt+' '+hour+':'+minutes+':'+seconds
	return date;
}
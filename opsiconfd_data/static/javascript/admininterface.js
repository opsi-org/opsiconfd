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
				console.log(element);
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
			printRPCCount(result.length);
			return result;
		} else {
			console.warn(request.statusText, request.responseText);
			return request.statusText;
		}
	});
	request.send();
}

function printRPCCount(rpcCount) {
	p = document.getElementById("rpc-count");
	let date = new Date(Date.now());
	htmlStr = "Number of RPCs since " + date.toLocaleString('en-US', {
		timeZone: 'UTC'
	}) + " (UTC): " + rpcCount;
	p.innerHTML = htmlStr;
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
				htmlStr += "<td class=\"rpc-td\">" + element[key] + "</td>";
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
		"params": [
			[],
			{}
		]
	}

	let option = document.getElementById("method-select");
	let method = option.options[option.selectedIndex].text;
	let inputs = document.getElementById("rpcInterface").getElementsByTagName("input");
	let parameter = [];

	apiJSON.method = method;

	try {
		for (i = 0; i < inputs.length; i++) {
			let name = inputs[i].name.trim();
			let value = inputs[i].value.trim();

			if (value) {
				parameter.push(JSON.parse(value));
			} else {
				if (name.indexOf("*", 1) == -1) {
					parameter.push(null);
				}
			}
		}
	} catch (e) {
		if (e instanceof SyntaxError) {
			console.log("JSON not valid... " + e);
		} else {
			console.log(e);
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
			// loadRPCTable("rpc_num", false);
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
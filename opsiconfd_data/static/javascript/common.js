var BASE_CONFIGED_DOWNLOAD_URL = "https://download.uib.de/4.2/stable/misc";
var CONFIGED_DOWNLOAD_LINKS = {
	"Windows": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-windows.exe`,
	"UNIX": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-linux.run`,
	"Linux": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-linux.run`,
	"MacOS": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-macos.sh`
}

function getOS() {
	userAgent = window.navigator.userAgent.toLowerCase();
	console.log(userAgent);
	if (userAgent.indexOf("windows") != -1) return "Windows";
	else if (userAgent.indexOf("mac") != -1) return "MacOS";
	else if (userAgent.indexOf("linux") != -1) return "Linux";
	else if (userAgent.indexOf("x11") != -1) return "UNIX";
	return "Windows";
}

function downloadConfiged() {
	let os = getOS();
	url = CONFIGED_DOWNLOAD_LINKS[os];
	window.open(url);
}

function ajaxRequest(method, url, body, requestInfos = false) {
	// console.debug("method: ", method);
	// console.debug("url: ", url);
	// console.debug("body: ", body);
	return new Promise(function (resolve, reject) {
		let req = new XMLHttpRequest();
		req.open(method, url);
		req.setRequestHeader("X-Requested-With", "XMLHttpRequest");
		req.onload = function () {
			if (req.status === 0 || (req.status >= 200 && req.status < 400)) {
				result = req.responseText;
				result = JSON.parse(result);
				if (requestInfos == true) {
					serverTiming = req.getResponseHeader("server-timing")
					resolve({ "data": result, "requestInfo": { "serverTiming": serverTiming } })
				}
				resolve(result);
			} else {
				console.error(`Request failed: ${req.status} - ${req.responseText}`);
				if (req.status == 401) {
					location.href = "/login";
				}
				if (req.responseText) {
					try {
						result = JSON.parse(req.responseText);
						console.error(result.message);
						reject(result);
					} catch {
						reject(req.responseText);
					}
				}
				else {
					console.log(`Error ${req.status}`);
					reject(`Error ${req.status}`)
				}
			}
		};
		if (body instanceof FormData) {
			req.send(body)
		}
		else if (body) {
			req.send(JSON.stringify(body))
		}
		else {
			req.send();
		}
	});
}

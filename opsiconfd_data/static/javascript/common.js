var BASE_CONFIGED_DOWNLOAD_URL = "https://download.uib.de/opsi4.2/misc/helper";
var CONFIGED_DOWNLOAD_LINKS = {
	"Windows": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-setup.exe`,
	"UNIX": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-linux-setup.tar.gz`,
	"Linux": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-linux-setup.tar.gz`,
	"MacOS": `${BASE_CONFIGED_DOWNLOAD_URL}/opsi-configed-linux-setup.tar.gz`
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

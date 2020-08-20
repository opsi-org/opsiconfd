var opsiVersion = "4.2";
var CONFIGED_DOWNLOAD_LINKS = {
	"Windows": "https://download.uib.de/opsi" + opsiVersion + "/misc/helper/opsi-configed-setup.exe",
	"UNIX": "https://download.uib.de/opsi" + opsiVersion + "/misc/helper/opsi-configed-linux-setup.tar.gz",
	"Linux": "https://download.uib.de/opsi" + opsiVersion + "/misc/helper/opsi-configed-linux-setup.tar.gz",
	"MacOS": "https://download.uib.de/opsi" + opsiVersion + "/misc/helper/opsi-configed-linux-setup.tar.gz"
}

function downloadConfiged(){
	let os = getOS();
	url = CONFIGED_DOWNLOAD_LINKS[os];
	window.open(url);
}

function getOS(){
	userAgent = window.navigator.userAgent.toLowerCase();
	if (userAgent.indexOf("windows") != -1) return "Windows";
	else if (userAgent.indexOf("mac") != -1) return "MacOS";
	else if (userAgent.indexOf("x11") != -1) return "UNIX";
	else if (userAgent.indexOf("linux") != -1) return "Linux";
	return "Windows";
}
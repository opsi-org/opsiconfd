function onLoad() {
	console.log("onLoad");
	let html = "";
	let os = getOS();
	let loc = window.location;
	let path = window.location.pathname.split("/")[1];
	if (!path) path = "dav";
	if (os == "Windows") {
		html = `Use address <pre>\\\\${loc.hostname}@SSL@\\${loc.port}\\${path}\\DavWWWRoot</pre> to open in Windows Explorer.`;
	}
	else if (os == "MacOS") {
		html = `Use address <pre>https://${loc.hostname}:${loc.port}/${path}</pre> to open in MacOS Finder.`;
	}
	else if (os == "Linux") {
		html = `Use address <pre>davs://${loc.hostname}:${loc.port}/${path}</pre> to open in file manager.`;
	}
	document.getElementById("mount-instructions").innerHTML = html;
}

function onClickTable(event) {
	// console.log(event);
}

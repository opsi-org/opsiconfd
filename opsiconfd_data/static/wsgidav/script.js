function onLoad() {
	console.log("onLoad");
	let html = "";
	let loc = window.location;
	let os = getOS();
	console.log(os);
	console.log(loc);
	if (os == "Windows") {
		html = `Use address <pre>\\\\${loc.hostname}@SSL@\\${loc.port}\\dav\\DavWWWRoot</pre> to open in Windows Explorer.`;
	}
	else if (os == "MacOS") {
		html = `Use address <pre>https://${loc.hostname}:${loc.port}/dav</pre> to open in MacOS Finder.`;
	}
	else if (os == "Linux") {
		html = `Use address <pre>davs://${loc.hostname}:${loc.port}/dav</pre> to open in file manager.`;
	}
	document.getElementById("mount-instructions").innerHTML = html;
}

function onClickTable(event) {
	// console.log(event);
}

import { spawnSync } from "node:child_process";

const files = [
	"../opsiconfd_data/static/javascript/admininterface.js",
	"../opsiconfd_data/static/javascript/common.js",
	"../opsiconfd_data/static/javascript/log_viewer.js",
	"../opsiconfd_data/static/javascript/memory_profiler.js",
	"../opsiconfd_data/static/javascript/welcome.js"
];

let failed = false;
for (const file of files) {
	const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
	if (result.status !== 0) {
		failed = true;
	}
}

if (failed) {
	process.exit(1);
}

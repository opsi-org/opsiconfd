function tracemallocSnapshot() {
    let limit = 25;
    document.getElementById("button-tracemalloc-snapshot").disabled = true;
    let request = new XMLHttpRequest();
    request.open("GET", `/admin/memory/tracemalloc-snapshot-new?limit=${limit}`);
    request.addEventListener('load', function (event) {
        if (request.status >= 200 && request.status < 300) {
            result = request.responseText;
            result = JSON.parse(result);
            outputToHTML(result.data, "memory-values");
            document.getElementById("button-tracemalloc-snapshot").disabled = false;
            return result;
        } else {
            console.warn(request.statusText, request.responseText);
            document.getElementById("button-tracemalloc-snapshot").disabled = false;
            return request.statusText;
        }
    });
    request.send()
}

function objgraphSnapshot(update = false) {
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
    if (snapshotNumber1 == "") {
        snapshotNumber1 = 1
    }
    if (snapshotNumber2 == "") {
        snapshotNumber2 = -1
    }
    url = "/admin/memory/diff?snapshot1=" + snapshotNumber1 + "&snapshot2=" + snapshotNumber2
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
    if (snapshotNumber1 == "") {
        snapshotNumber1 = 1
    }
    if (snapshotNumber2 == "") {
        snapshotNumber2 = -1
    }
    url = "/admin/memory/guppy/diff?snapshot1=" + snapshotNumber1 + "&snapshot2=" + snapshotNumber2
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
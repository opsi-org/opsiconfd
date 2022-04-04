// opsi welcome.js

function onLoad() {
    let userLang = navigator.language || navigator.userLanguage;
    let lang = "en"
    if (userLang == "de-DE") {
        lang = "de"
    }

    content = document.getElementsByClassName(lang)
    console.log(content);
    console.log(typeof (content));
    for (var i = 0; i < content.length; i++) {
        content[i].style.visibility = "visible";
        content[i].style.display = "block";
    }
}


function deactivateWelcomePage() {
    let request = new XMLHttpRequest();
    request.open("POST", "/welcome/deactivate");
    request.addEventListener('load', function (event) {
        if (request.status >= 200 && request.status < 300) {
            result = request.responseText;
            result = JSON.parse(result);
            console.log(result);
            let skip = document.getElementById("skip");
            skip.disabled = true;
            return result;
        } else {
            console.warn(request.statusText, request.responseText);
            return request.statusText;
        }
    });
    request.send()
}

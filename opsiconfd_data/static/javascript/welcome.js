// opsi welcome.js
function redirectToAdminPage() {

    let skip = document.getElementById("skip");
    console.log(skip.checked);
    if (skip.checked == true) {
        let request = new XMLHttpRequest();
        request.open("POST", "/welcome/deactivate");
        request.addEventListener('load', function (event) {
            if (request.status >= 200 && request.status < 300) {
                result = request.responseText;
                result = JSON.parse(result);
                console.log(result);
                return result;
            } else {
                console.warn(request.statusText, request.responseText);
                return request.statusText;
            }
        });
        request.send()
    }
    window.open("/admin")

}

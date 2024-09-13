const resetBtn = document.querySelector("#reset-btn")
const email = document.querySelector("#id_email")
const loading = document.querySelector("#loading")
const errorsBlock = document.querySelector("#errors")

const DOMAIN = document.querySelector("#domain").dataset.key
const ISSECURE = document.querySelector("#domain").dataset.method === "True"
const APIRESETURL = document.querySelector("#domain").dataset.hrefTemplate

function clearLoadingBtn(message, error = false){
    loading.innerHTML = ""
    errorsBlock.innerHTML = `
        <div class="alert alert-${error ? 'danger' : 'success'} alert-dismissible" role="alert">
        <div id="form_errors">
            <strong>${message}</strong>
        </div>
    </div>
    `
}

function handleSuccess(json){
    clearLoadingBtn(json["detail"])
}

function handleError(json){
    clearLoadingBtn(json["email"], true)
}

function handleResponse(response){
    if (response.ok){
        response.json().then(handleSuccess)
    } else {
        response.json().then(handleError)
    }
}

function resetPassword(){
    if (email.value != ""){
        loading.innerHTML = `
            <div class="lds-ring"><div></div><div></div><div></div><div></div></div>
        `
        fetch("http" + (ISSECURE ? "s" : "") + "://" + DOMAIN + APIRESETURL, {
          method: "POST",
          body: JSON.stringify({
            "email": email.value
          }),
          headers: {
            "Content-type": "application/json; charset=UTF-8"
          }
        }).then(handleResponse)
        .catch((error) => handleError({email: "Ошибка сети."}))
    }
}

resetBtn.onclick = resetPassword

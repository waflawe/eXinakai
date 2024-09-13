const action = document.querySelector("div.action")
const message = document.querySelector("div.message")

function clear(toClear) {
    return () => {
        toClear.parentElement.parentElement.removeChild(toClear.parentElement)
    }
}

if (action) {
    action.onclick = clear(action)
}
if (message) {
    message.onclick = clear(message)
}

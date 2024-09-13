const generateBtn = document.querySelector("#generate-btn")
const resultInput = document.querySelector("#random-password")
const password1 = document.querySelector("#password1")
const password2 = document.querySelector("#password2")

const lengthInput = document.querySelector("#lengthinput")
const lowercase = document.querySelector("#lowercase")
const uppercase = document.querySelector("#uppercase")
const digits = document.querySelector("#digits")
const punctuation = document.querySelector("#punctuation")

const LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const DIGITS = "0123456789"
const PUNCTUATION = ".,;*&$#@%!?"

function generatePassword(event){
    const length = lengthInput.value
    let charset = ""
    let password = ""

    if (!lowercase.checked && !uppercase.checked && !digits.checked && !punctuation.checked){
        charset += LOWERCASE + UPPERCASE + DIGITS + PUNCTUATION
    } else {
        charset += lowercase.checked ? LOWERCASE : ""
        charset += uppercase.checked ? UPPERCASE : ""
        charset += digits.checked ? DIGITS : ""
        charset += punctuation.checked ? PUNCTUATION : ""
    }

    for (let i = 0, n = charset.length; i < length; ++i){
        password += charset.charAt(Math.floor(Math.random() * n))
    }

    resultInput.value = password
    password1.value = password
    password2.value = password
}

generateBtn.onclick = generatePassword

generatePassword()

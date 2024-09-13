const arrowDown = `
    <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" fill="currentColor" class="bi bi-caret-down-fill ml" viewBox="0 0 15 15">
      <path d="M7.247 11.14 2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z"/>
    </svg>
`
const arrowRight = `
    <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" fill="currentColor" class="bi bi-caret-right-fill ml" viewBox="0 0 15 15">
      <path d="m12.14 8.753-5.482 4.796c-.646.566-1.658.106-1.658-.753V3.204a1 1 0 0 1 1.659-.753l5.48 4.796a1 1 0 0 1 0 1.506z"/>
    </svg>
`
const DOWN = 'down'
const RIGHT = 'right'

const dropdownBtns = [...document.querySelectorAll('.collection .dropdown-button')]
const cache = []

class Dropdown {
    constructor(button, status, index) {
        this.button = button
        this.status = status
        this.index = index
    }
}

class CachedDropdown {
    constructor(dropdown, passwordsHTML) {
        this.dropdown = dropdown
        this.passwordsHTML = passwordsHTML
    }
}

function hidePasswords(dropdownBtn) {
    allPasswords = document.querySelector(`#collection${dropdownBtn.index} .collection-passwords`)
    flag = false
    cache.forEach((element) => {
        if (element.dropdown === dropdownBtn) {
            flag = true
        }
    })
    if (!flag) {
        cache.push(new CachedDropdown(dropdownBtn, allPasswords.innerHTML))
    }
    allPasswords.innerHTML = ''
}

function showPasswords(dropdownBtn) {
    allPasswords = document.querySelector(`#collection${dropdownBtn.index} .collection-passwords`)
    if (allPasswords.innerHTML != '') {
        return
    }
    cache.forEach((element) => {
        if (element.dropdown === dropdownBtn) {
            allPasswords.innerHTML = element.passwordsHTML
        }
    })
}

function changeDropdownButtonStatus(dropdownBtn) {
    return () => {
        dropdownBtn.button.innerHTML = dropdownBtn.status === DOWN ? arrowRight : arrowDown
        dropdownBtn.status = dropdownBtn.status === DOWN ? RIGHT : DOWN
        if (dropdownBtn.status === DOWN) {
            showPasswords(dropdownBtn)
        } else if (dropdownBtn.status === RIGHT) {
            hidePasswords(dropdownBtn)
        }
    }
}

dropdownBtns.map((btn, index) => {
    button = new Dropdown(btn, DOWN, index)
    btn.innerHTML = arrowDown
    btn.onclick = changeDropdownButtonStatus(button)
    return button
})

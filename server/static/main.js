const form = document.getElementById('login-form')
const username = document.getElementById('username')
const password = document.getElementById('password')
const submit = document.getElementById('submit')

/**
 * Sends login request to the server
 * @param {SubmitEvent} event
 */
form.onsubmit = async (event) => {
  event.preventDefault()
}

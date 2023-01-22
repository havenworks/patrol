const form = document.getElementById('login-form')
const username = document.getElementById('username')
const password = document.getElementById('password')
const submit = document.getElementById('submit')

/**
 * Sends the login request to the server
 * @param {SubmitEvent} event
 */
form.onsubmit = async (event) => {
  event.preventDefault()

  const res = await fetch('/api/users/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: username.value,
      password: password.value
    })
  })

  if (res.ok) {
    location.replace('/app')
  }
}

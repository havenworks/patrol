const crypto = window.crypto

const form = document.getElementById('login-form')
const username = document.getElementById('username')
const password = document.getElementById('password')

const key = null

document.onload = async () => {
  const req = await fetch('/.well-known/jwks.json')
  const res = await req.json()

  const rawKeys = res.keys.filter($ => $.key_ops.includes('encrypt'))
  const rawKey = rawKeys[Math.floor(Math.random() * rawKeys.length)]

  const key = await crypto.subtle.importKey('jwk', rawKey, {
    name: 'RSA-OAEP',
    hash: 'SHA-512'
  }, false, rawKey.key_ops)

  console.log(key)
}

/**
 * Sends login request to the server
 * @param {SubmitEvent} event
 */
form.onsubmit = (event) => {
  event.preventDefault()
}

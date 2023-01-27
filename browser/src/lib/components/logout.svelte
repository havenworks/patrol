<script lang="ts">
  const logout = async () => {
    const res = await fetch('/api/users/logout', {
      method: 'DELETE',
      credentials: 'same-origin'
    })
    console.log(await res.text())

    location.replace('/')
  }
</script>

<button on:click={logout}>Logout</button>

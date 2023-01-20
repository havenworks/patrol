<script lang="ts">
  if (
    document.cookie
      .split(';')
      .some((cookie) => cookie.trim().startsWith('_patrol_key='))
  )
    location.replace('/')
</script>

<slot />

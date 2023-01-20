<script lang="ts">
  import { browser } from '$app/environment'

  if (
    browser &&
    document.cookie
      .split(';')
      .some((cookie) => cookie.trim().startsWith('_patrol_key='))
  )
    location.replace('/')
</script>

<slot />

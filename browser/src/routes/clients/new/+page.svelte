<script lang="ts">
  import { createClient, type NewClient } from '$lib/api/client'

  let newClient: NewClient
</script>

<form on:submit|preventDefault={() => createClient(newClient)}>
  <input type="text" bind:value={newClient.name} />
  <input type="url" bind:value={newClient.homepage_url} />
  <input type="" />
</form>

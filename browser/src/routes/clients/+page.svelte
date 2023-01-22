<script lang="ts">
  import type { PageData } from './$types'

  export let data: PageData
</script>

{#each data.clients as client}
  <div>{client.id}</div>
{/each}

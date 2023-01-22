import type { PageLoad } from './$types'

export const load: PageLoad = async () => {
  const res = await fetch('http://localhost:8000/api/clients')
  return {
    clients: await res.json()
  }
}

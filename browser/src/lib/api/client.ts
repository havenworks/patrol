import { z } from 'zod'
import { apiFetch } from '.'

export const client = z.object({
  id: z.string().uuid(),

  name: z.string(),
  homepage_url: z.string().url(),
  logo: z.string(),
  logo_url: z.string().url(),

  redirect_uris: z.array(z.string().url()),
  grant_types: z.array(z.string())
})

export type Client = z.infer<typeof client>

export type NewClient = Omit<Client, 'id' | 'logo' | 'logo_url'>

export const createClient = async (
  newClient: NewClient
): Promise<{ client: Client, secret: string }> => {
  const response = await apiFetch('/api/clients', {
    method: 'POST',
    body: JSON.stringify(newClient)
  })

  return await z
    .object({
      secret: z.string(),
      client
    })
    .parseAsync(await response.json())
}

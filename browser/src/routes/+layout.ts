import { redirect } from '@sveltejs/kit'
import type { LayoutLoad } from './$types'

export const ssr = false
export const prerender = true

export const load: LayoutLoad = async () => {
  if (
    !document.cookie
      .split(';')
      .some((cookie) => cookie.trim().startsWith('_patrol_key='))
  ) {
    console.info('Redirecting to login')
    redirect(307, '/')
  }
}

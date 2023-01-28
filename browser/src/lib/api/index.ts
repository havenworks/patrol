export const apiFetch = async (
  url: string,
  options: RequestInit = {},
  json: boolean = true
): ReturnType<typeof fetch> => {
  return await fetch(url, {
    ...options,
    headers: json
      ? { ...options.headers, 'Content-Type': 'application/json' }
      : options.headers
  })
}

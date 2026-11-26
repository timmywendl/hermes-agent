/** Both native event seconds and API observation timestamps retain their source clock. */
export function workbenchTime(value: number | string) {
  return new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString()
}

export function missionDescription(body: null | string | undefined) {
  if (!body) {
    return ''
  }

  try {
    const parsed: unknown = JSON.parse(body)

    if (parsed && typeof parsed === 'object' && 'description' in parsed && typeof parsed.description === 'string') {
      return parsed.description
    }
  } catch {
    // Ordinary task bodies are plain text; only the plan envelope needs unwrapping.
  }

  return body
}

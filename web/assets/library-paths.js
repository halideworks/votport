// Paths returned by the authenticated library listing are relative file paths.

export function parseLibraryPath(path) {
  const value = String(path || '');
  if (!value || value.startsWith('/') || value.includes('\\')) return null;
  const parts = value.split('/');
  return parts.some((part) => !part || part === '.' || part === '..') ? null : parts;
}

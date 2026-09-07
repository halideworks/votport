// Paths returned by the authenticated library listing are relative file paths.

export function parseLibraryPath(path) {
  const value = String(path || '');
  if (!value || value.startsWith('/') || value.includes('\\')) return null;
  const parts = value.split('/');
  return parts.some((part) => !part || part === '.' || part === '..') ? null : parts;
}

export function retainLibraryProjectSuggestions(suggestions, directories, current, limit) {
  for (const directory of directories) suggestions.add(directory);
  if (current) {
    suggestions.delete(current);
    suggestions.add(current);
  }
  for (const entry of [...suggestions].slice(0, -limit)) suggestions.delete(entry);
}

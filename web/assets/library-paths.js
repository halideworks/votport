// Paths returned by the authenticated library listing are relative file paths.

export function projectDirectoryPrefixes(files) {
  const directories = new Set();
  for (const file of files) {
    const path = String(file.path || '');
    if (!path || path.startsWith('/') || path.includes('\\')) continue;
    const parts = path.split('/');
    if (parts.some((part) => !part || part === '.' || part === '..')) continue;
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(parts.slice(0, index).join('/'));
    }
  }
  return [...directories].sort();
}

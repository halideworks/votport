// Paths returned by the authenticated library listing are relative file paths.

export function parseLibraryPath(path) {
  const value = String(path || '');
  if (!value || value.startsWith('/') || value.includes('\\')) return null;
  const parts = value.split('/');
  return parts.some((part) => !part || part === '.' || part === '..') ? null : parts;
}

export function projectDirectoryPrefixes(files) {
  const directories = new Set();
  for (const file of files) {
    const parts = parseLibraryPath(file.path);
    if (!parts) continue;
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(parts.slice(0, index).join('/'));
    }
  }
  return [...directories].sort();
}

export function buildLibraryTree(files) {
  const root = { name: '', path: '', children: new Map(), files: [] };
  for (const file of files) {
    const parts = parseLibraryPath(file.path);
    if (!parts) continue;
    let node = root;
    for (const [index, name] of parts.slice(0, -1).entries()) {
      const path = parts.slice(0, index + 1).join('/');
      if (!node.children.has(name)) {
        node.children.set(name, { name, path, children: new Map(), files: [] });
      }
      node = node.children.get(name);
    }
    node.files.push(file);
  }
  return root;
}

export function libraryTreeNode(root, path) {
  const parts = path ? parseLibraryPath(path) : [];
  if (!parts) return null;
  let node = root;
  for (const part of parts) {
    node = node.children.get(part);
    if (!node) return null;
  }
  return node;
}

export function libraryFilesIn(node) {
  const files = [...node.files];
  for (const child of node.children.values()) files.push(...libraryFilesIn(child));
  return files;
}

export function filterLibraryFiles(files, query) {
  const needle = String(query || '').trim().toLowerCase();
  return files.filter((file) => {
    const path = String(file.path || '');
    return parseLibraryPath(path) && (!needle || path.toLowerCase().includes(needle));
  });
}

export function toggleFolderSelection(selectedPaths, folderPaths, max = 64) {
  const paths = [...new Set(folderPaths)];
  const selected = new Set(selectedPaths);
  const allSelected = paths.length > 0 && paths.every((path) => selected.has(path));
  if (allSelected) {
    for (const path of paths) selected.delete(path);
    return selected;
  }
  const additions = paths.filter((path) => !selected.has(path));
  if (selected.size + additions.length > max) return null;
  for (const path of additions) selected.add(path);
  return selected;
}

export function selectedLibraryStats(files, selectedPaths) {
  const selected = new Set(selectedPaths);
  let bytes = 0;
  let count = 0;
  for (const file of files) {
    if (!selected.has(file.path)) continue;
    count += 1;
    bytes += Number(file.bytes) || 0;
  }
  return { count, bytes };
}

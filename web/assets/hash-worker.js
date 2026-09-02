// votport hash worker: owns the vot-wasm hash trees so the UI thread never
// blocks on hashing, and serves range proofs from them during upload.
// VOTPORT PROPRIETARY LICENSE.

import init, {
  ObjectBuilder,
  PreparedObject,
  Suite,
  proofLeavesAt,
} from '/assets/vendor/vot_wasm.js';

// A multiple of the 64 KiB proof leaf, so every read starts on a leaf.
const HASH_READ_BYTES = 8 * 1024 * 1024;
const prepared = new Map(); // key -> PreparedObject (the merkle tree)
const ready = init();

self.onmessage = async ({ data: message }) => {
  const { op, req, key } = message;
  try {
    await ready;
    if (op === 'hash') {
      const { file } = message;
      const size = BigInt(file.size);
      const builder = new ObjectBuilder(Suite.Blake3Bao64, size, size);
      const readAt = (offset) =>
        file.slice(offset, Math.min(offset + HASH_READ_BYTES, file.size)).arrayBuffer();
      let offset = 0;
      // Overlap one read with hashing, mirroring the old main-thread loop.
      let pending = file.size > 0 ? readAt(0) : null;
      while (pending) {
        const bytes = new Uint8Array(await pending);
        offset += bytes.length;
        pending = offset < file.size ? readAt(offset) : null;
        builder.update(bytes);
        postMessage({ req, step: bytes.length });
      }
      const object = builder.finish();
      prepared.set(key, object);
      const id = object.objectId;
      postMessage({ req, done: { suite: id.suite, root: id.root, length: id.length } });
    } else if (op === 'leaves') {
      // One segment of a file hashed in parallel: the proof leaves for
      // [start, end), which the owner joins with the other segments'.
      const { file, start, end } = message;
      const parts = [];
      let offset = start;
      let pending = readSlice(file, offset, end);
      while (pending) {
        const bytes = new Uint8Array(await pending);
        const next = offset + bytes.length;
        pending = next < end ? readSlice(file, next, end) : null;
        parts.push(proofLeavesAt(Suite.Blake3Bao64, BigInt(offset), bytes));
        offset = next;
        postMessage({ req, step: bytes.length });
      }
      const leaves = concat(parts);
      postMessage({ req, done: leaves }, [leaves.buffer]);
    } else if (op === 'assemble') {
      // The owner keeps the tree built from the joined leaves, exactly as if
      // it had hashed the file itself.
      const { length, leaves } = message;
      const size = BigInt(length);
      const object = PreparedObject.fromProofLeaves(Suite.Blake3Bao64, size, concat(leaves), size);
      prepared.set(key, object);
      const id = object.objectId;
      postMessage({ req, done: { suite: id.suite, root: id.root, length: id.length } });
    } else if (op === 'prove') {
      const proof = prepared.get(key).prove(message.offset, message.length);
      const bytes = proof.bytes();
      postMessage(
        {
          req,
          done: {
            coveredOffset: proof.coveredOffset,
            coveredLength: proof.coveredLength,
            bytes,
          },
        },
        [bytes.buffer],
      );
    } else if (op === 'drop') {
      prepared.get(key)?.free?.();
      prepared.delete(key);
    }
  } catch (error) {
    postMessage({ req, error: String(error?.message || error) });
  }
};

function readSlice(file, offset, end) {
  return file.slice(offset, Math.min(offset + HASH_READ_BYTES, end)).arrayBuffer();
}

function concat(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

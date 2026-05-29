# backup-fs storage design

`startos-backup-fs` is a FUSE filesystem whose backing store is an
encrypted, error-corrected, block-chunked directory tree. It is built to be
written through to physically-attached USB drives of any filesystem, to
CIFS shares, and to `rclone mount` backends (S3, SFTP, SSHFS, …), and to be
copied incrementally with `rsync`/`rclone`.

## On-disk layout

```
$data_dir/
  cryptinfo            sealed (PBKDF2) master key + IVs
  inode_pool           sealed free-inode allocator
  inodes/<bucket>/<id> one sealed file per inode (metadata + dir contents)
  contents/<bucket>/<name>   sealed content blocks, ≤ 1 MiB of plaintext each
```

Every object on disk is a **sealed blob** (see `vault.rs`). A file's data is
split into fixed-size **blocks** (see `blockstore.rs`); each block is its own
sealed file.

## Sealed blobs: encryption + integrity + ECC (`vault.rs`, `ecc.rs`)

`seal(plaintext)` →

1. `secret = plaintext || SHA-256(plaintext)`
2. encrypt `secret` with ChaCha20 under a fresh random nonce
3. split the ciphertext into `data` Reed-Solomon shards and compute
   `parity` extra shards (default 10 + 2, tunable via `BACKUPFS_ECC_DATA` /
   `BACKUPFS_ECC_PARITY`); store a CRC-32 with each shard

`open(blob)` verifies each shard's CRC, treats any failing shard as an
erasure, Reed-Solomon-reconstructs the ciphertext if **≤ parity** shards are
bad, decrypts, and checks the SHA-256 tag. The tag both detects residual
corruption and rejects a wrong password (`BadChecksum`).

ECC is computed over **ciphertext**, so on-medium bit rot is repaired before
decryption. Each block carries its own parity, so corruption in one block
never spreads to the rest of a file.

## Block-chunked content (`blockstore.rs`, `contents.rs`)

A regular file is `ceil(size / 1 MiB)` blocks. Writes do read-modify-write at
block granularity and a block is always written **whole** — buffered, then
atomically renamed into place. This is the core of the redesign:

* **No random writes into existing objects.** Backends that can only replace
  an object wholesale (S3/`rclone`) never see a sub-object overwrite; a small
  edit rewrites one ≤ 1 MiB block, not the whole file.
* **Cheap incremental backup.** A block's filename is a stable keyed
  SHA-256 of `(content_id, block_index)`. Editing one region rewrites exactly
  one block file and leaves every other block byte-for-byte identical, so
  `rsync`/`rclone` of `$data_dir` transfer only the changed blocks.
* **Small and large files both behave.** A tiny file is one small block file;
  a huge file is many independent blocks written/verified in parallel.
* **Sparse files** cost nothing for holes — unwritten blocks have no file on
  disk and read back as zeros.

## Cache-deadlock avoidance

Content blocks are read and written with `O_DIRECT` (via the aligned-I/O
buffer in `aligned_io.rs`, with an io_uring fast path, network-FS-aware flush
chunking, and a flush timeout). This keeps file data out of the kernel page
cache, avoiding the CIFS writeback deadlock where freeing memory needs a
flush and the flush needs memory. Small metadata goes through the page cache
and is made durable by the batched `syncfs` group-commit.

## Preserved Linux inode attributes

Inode metadata stores mode, uid/gid, atime/mtime/ctime/crtime, and the full
xattr map — so **POSIX ACLs** (`system.posix_acl_access` /
`system.posix_acl_default`) round-trip like any other xattr. `mknod` supports
regular files, directories, symlinks, FIFOs, sockets, and character/block
devices (with `rdev` preserved).

## What carried over unchanged

The inode/handle/controller layer — directory bookkeeping, the dirty-inode
coalescing cache, the clean-load LRU, crash-consistent rename/unlink/GC
ordering, the sharded worker pool, and the `syncfs` group-commit durability
path — is retained from the previous design; only the content-storage and
serialization layers were replaced.

## Small-file packing (log-structured metadata)

Layered on top of the block design to cut the per-file backing-store object
count, which dominates many-small-files backups to CIFS/rclone:

- **Hash-bucketed directories (Stage 1, shipped).** A directory's entries no
  longer live inline in its inode once it grows large; they spill into
  hash-bucketed sealed files, so a create touches one bucket (O(1)) instead
  of rewriting the whole listing (O(n) → O(n²) to build a directory).

- **Inodes in a log (Stage 3, shipped).** Inodes are append-only records in
  shared segment files (`segments/`, see `seglog.rs`), not one file per
  inode. A monotonic allocator + replay-rebuilt index; tombstone-on-delete
  durable before content removal.

- **Inline tiny content (Stage 5, shipped).** A file ≤ 4 KiB stores its bytes
  directly in its inode record — zero extra content objects. Larger files
  migrate to per-file 1 MiB block files.

### Planned: shared content packing for sub-block files (NOT yet implemented)

**Gap.** A file between the inline threshold (4 KiB) and one chunk (1 MiB)
still gets exactly one block file of its own — a partially-filled object. A
workload dominated by, say, 64 KiB files therefore still pays one
CREATE+RENAME per file. Inline packing handles the tiny tail; this stage
would handle the medium range.

**Approach.** Pack multiple sub-block file contents into shared, append-only
**content-pack** segments (a content-side analogue of the inode `seglog`,
and likely reusing that machinery). A small file's content reference becomes
`(pack_segment, offset, len)` instead of `(content_id, block_index)`; its
bytes are appended to the active content pack. Files ≥ 1 MiB keep their own
block files; files ≤ 4 KiB stay inline. So the packed range is roughly
`(4 KiB, 1 MiB)`.

**Garbage collection (the hard part, explicitly accepted).** Deleting or
overwriting a packed file leaves dead space in a pack. Reclaim lazily:
mark-deleted (drop the index/inode reference), and run a **threshold-gated
compaction pass** when a pack's dead-space ratio crosses a bound — copy the
still-live extents into a fresh pack, repoint the referencing inodes, then
delete the old pack (durable-before-delete, mirroring the inode log).
Optimize for speed over disk footprint: tolerate dead space until the
threshold, then compact in bulk. Reuse `seglog`'s seq-ordered replay,
forward-resync, and per-record sealing (ChaCha20 + Reed-Solomon ECC).

**Trade-offs / open questions.**
- *Incremental backup*: a content pack mutates as it's appended, so rsync/
  rclone re-send the active pack; compaction rewrites packs. Same
  active-segment-churn trade-off as the inode log — sealed packs stay
  immutable until compaction, so the cost is bounded and threshold-tunable.
- *Compaction vs. offsite bandwidth*: rewriting a pack re-transfers its live
  bytes; gate compaction on a high dead-ratio + a minimum interval, and
  prefer near-dead packs (verbatim-copy live frames to keep bytes stable).
- *Worth it?* Only if medium (4 KiB–1 MiB) files dominate the target
  workload. **Gated on benchmarking the shipped stages first** — the
  inline + inode-log packing may already capture most of the win for the
  tiny-file-heavy case, in which case this stage's GC complexity is not
  worth the squeeze.

### Other deferred items (space/robustness, not correctness)

- Compaction of the **inode** log segments (dead inode-record reclamation),
  and streamed multi-generation checkpoints for fast remount on huge stores.
- A `find_orphans` sweep to reclaim directory bucket / content files orphaned
  by a crash mid-reshard or mid-GC.
- `fsync` of parent directories in `AtomicFile` (durability currently rides
  the trailing `syncfs`).

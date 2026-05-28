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

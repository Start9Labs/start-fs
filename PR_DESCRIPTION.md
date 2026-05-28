## Summary
- Replaced one-content-file-per-file storage with encrypted immutable 1 MiB chunk objects and encrypted inode manifests.
- Added simple dependency-free ECC per chunk: 16 data shards + XOR parity + per-shard SHA-256, recovering one corrupt shard and rejecting multi-shard corruption.
- Preserved richer Linux inode state: rdev/flags, FIFO/socket/block/char device kinds, xattrs and POSIX ACL xattrs, plus ACL-aware access checks for `system.posix_acl_access`.
- Switched chunk writes to whole-file sequential atomic writes with `posix_fadvise(POSIX_FADV_DONTNEED)` to reduce CIFS/rclone page-cache pressure; O_DIRECT metadata paths now fall back to buffered I/O on backends that reject it.
- Added sparse/truncate safety so truncated tail bytes do not reappear after re-extension.

## Tests
- `cargo test --workspace --all-features`
  - 33 passed, 1 ignored benchmark
- Added coverage for chunk ECC recovery/rejection, large-file chunk object counts, truncate/re-extend zeroing, POSIX ACL xattr persistence, and FIFO type persistence.

## Benchmark
Command:

```bash
cargo test --workspace --all-features benchmark_chunk_codec -- --ignored --nocapture
```

Result on this dev container:

```text
chunk codec benchmark: write 731.4 MiB/s, read 537.1 MiB/s (64 MiB)
```

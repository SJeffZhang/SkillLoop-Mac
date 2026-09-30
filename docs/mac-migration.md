# Mac migration execution record

The Mac deployment is a new experiment configuration. DGX evidence is read-only
history; its SGLang/FP8 outcomes must not be counted as Ollama/MXFP8 runs.
M0–M5 are inherited by digest and independent evidence reduction, without model
calls. M6 candidates, failures, and cases are inherited as inputs, but the new
M6 gate needs its own 42 order, 66 refund, and 48 Markdown paired runs.

## Source seal and import

On 2026-09-30 the DGX had no M6/M7 or SGLang worker process, no test container,
and no crontab. The port 8888 showcase and its private source remained running.
The DGX SQLite online backup API copied all 593 `.db`/`.sqlite` files with zero
errors. The private import is under `local-data/dgx-import/`, ignored by Git.
The original directories, including WAL files, and the consistent SQLite backups
are kept separately. `SHA256SUMS.dgx` lists the DGX file hashes, and
`SYMLINKS.dgx.json` records 17 symbolic links without dereferencing them. On
2026-09-30 the full Mac verification passed: 36,307 files, 32,424,623,231
bytes, 17 symbolic links, and 593 consistent SQLite backups. The source and
backup directories were then set read-only for the current user. The private
`local-data/dgx-import/verification.json` records the check and 246,169,600,000
free bytes at the time. Recheck from the import directory with:

```sh
shasum -a 256 -c SHA256SUMS.dgx
```

The Mac's FileVault is enabled. Keep the private import root at 0700 and its
manifests at 0600; the sealed source tree has read-only owner access. Preserve a separate encrypted
external copy if free space would fall below 50 GiB. Never add `local-data` to
Git or place credentials in a command line, log, or report.
`scripts/mac_inherit_dgx.py` creates a private, hash-based index of historical
M6 result files without model requests. The first import indexed 282 result
files across 18 campaign/config/profile groups with no structural errors.
The 1,128 observation, evaluation, and evidence envelopes in those records
passed schema and digest validation. The accepted M5 gate and two historical M6
gate receipts passed self-digest checks. These remain historical DGX outcomes
and give zero Mac Ollama Gate credit. Independent per-run reduction has since verified 136 attempts from selected historical M6 batches, with zero errors and zero model calls (132 complete; 8 confirmed failures). Full historical M6 Gate reduction remains pending.

## Runtime admission

Install a pinned native Ollama release and pull `qwen3.8:27b-mxfp8`. Record the
Ollama version, local model manifest digest, template, tokenizer, and parameters
in a new immutable `config_id`. The old `+66` SGLang token adjustment is invalid
on this backend. `OllamaGateway` refuses formal runs unless a measured Ollama
template offset is supplied; each response compares its `prompt_eval_count`
with the preflight count and fails closed on drift. The runtime uses native
`/api/chat` with `think:false`. The scanner bridge retains `--network none`
for its guest and accepts only model endpoints over a restricted Unix socket.
`scripts/mac_ollama_calibrate.py` performs five fixed local probes and emits a
private calibration record. The offline tokenizer reads the imported pinned
tokenizer snapshot. A single offset is only an initial check; tool return
turns, maximum profile contexts, and scanner payloads must match before a
formal `config_id` is frozen.

Run the trusted Proxy, Runtime, scanner bridge, and authoritative SQLite inside
the Docker Desktop Linux VM. Do not put Unix sockets or live SQLite on the
macOS file share. Enable and verify Docker Desktop host networking before a
container is allowed to reach host Ollama. Make an online SQLite backup before
exporting each run to the Mac private directory. Calibrate and verify tool
calls, refusal recovery, 16K context, usage, latency, memory, timeout, scanner
coverage, and Linux UID/permission boundaries before freezing per-profile
budgets. If the 32 GB model cannot fit reliably, leave formal M6 pending.

Docker Desktop 4.93.0 was installed from the official ARM64 disk image. Its
Mac SHA-256 matched the transferred digest
`bf062f45334c711bd2fc2ed47a5588d050fbb950be3ae3aa4ac9826f04ad4dba`;
`hdiutil verify` and the unsandboxed macOS code signature check passed. The
first launch failed because a Homebrew `md5sum` alias preceded Apple's `/sbin/md5`
in the process PATH. Relaunching Docker with `/sbin` first fixed startup without
changing the user's global PATH. `HostNetworkingEnabled` was set to true, and an
ARM64 Linux container fetched a loopback-only Mac HTTP endpoint over
`--network host`. The imported scanner OCI image ID is
`sha256:165f1d7ae6e878970136b78bda4fb9b7cc5a52d305734f7d3b6318d6434ffe9c`.

## Stage order

1. M6: freeze new config and plans by profile; reuse inherited cases and
   candidates; execute required paired runs; independently reduce raw evidence.
2. M7: create fresh private epochs; run submitted and finalist under the same
   suite, three times per case, with separate development/protection Ollama
   lifecycles and private logs. Missing evidence is inconclusive.
3. M8: use only synthetic Skills in `SJeffZhang/skillloop-ci-test`; restore
   `SJeffZhang` GitHub auth, configure the App and independent fork identity,
   then verify exact SHA, force-push, duplicate events, config changes, old
   workers, and resumed evaluation.
4. M9: complete independent order, refund, and Markdown campaigns and publish
   engineering and business conclusions for each. Keep the existing order Demo
   acceptance as its own historical result.
5. M10: pair proven attacks before and after repair, then rehearse cancellation,
   archive, SQLite restore, disk and queue capacity. A restored deployment gets
   a new epoch and does not inherit old qualifications.

Each stage freezes source and configuration before model calls, then invokes an
independent Gate on raw evidence. Reports must state completed, incomplete,
confirmed failure, and actual attempts separately. Only reviewed redacted
reports may update the DGX public showcase.


## Approved Mac isolation decision — 2026-10-01

The user selected fresh containers for each agent execution, with fresh writable
volumes and run identities, rather than adding an Ubuntu VM for AppArmor.
[Mac PRD](../SkillLoop-PRD-Mac.zh-CN.md) and
[Mac runtime profile](../specs/mac/runtime-profile.json) define this deployment.
AppArmor is not required for Mac; the immutable DGX profile is retained.
Agent/scanner networking must be disabled and replaced by restricted Linux Unix
socket interfaces. Shared model weights do not imply isolated model caches:
development and protection require separate service lifecycles, caches and logs.
The current host-networked diagnostic runner is not this final implementation.

The fork is `https://github.com/SJeffZhang/SkillLoop-Mac`; Git stores source and
sanitized progress. Raw evidence, model stores, databases and credentials remain
private. Formal M6 runs are still zero. The 42/66/48 draft paired plans reuse
inherited candidates and suites and have a separate Mac config identity.
The empty M8 synthetic repository exists at
`https://github.com/SJeffZhang/skillloop-ci-test`; App and independent fork tests
remain pending.

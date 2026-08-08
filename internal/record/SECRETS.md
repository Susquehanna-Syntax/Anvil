# SECRETS.md — Retention, Deletion, and What Anvil Does Not Guarantee

**Status: honesty document.** It exists to stop a reader believing Anvil erases anything. It describes
no feature. Every security claim below is transcribed from `research/08-buffer-and-handoff.md`, which
sourced it first; every claim about this repository cites the file that makes it true.

| | |
|---|---|
| Owning step | `R.9`, `plan/40-record-and-storage.md` |
| Source of every security claim | `research/08-buffer-and-handoff.md` (§F "Buffer security", §"Risks, Dissent And Failure Modes") |
| Binding spine text | `plan/00-SPINE.md` S1 item 5 |
| Related code | `internal/store/schema.sql`, `internal/store/ddl.go`, `internal/store/migrate.go` |

---

## 0. The whole document in four sentences

1. **Nothing in this repository securely erases anything.** No code path here overwrites, shreds,
   crypto-erases, or otherwise sanitises the tmpfs packet, the `audit_record.payload` blob, or any
   database row.
2. **`shred` would not fix that**, and Anvil must not pretend otherwise: on the filesystems and storage
   Anvil actually runs on, `shred` cannot work.
3. **The 8-hour window is a claim timeout, not a confidentiality control.** It bounds how long an
   unclaimed finding stays eligible for a coding agent. It bounds nothing about who can read what.
4. **If confidentiality-at-rest is a requirement, the control is a per-scan LUKS2 volume or `fscrypt` —
   volume/filesystem encryption with key destruction — not application-level deletion.**

If you finish this document feeling reassured, re-read section 2.

---

## 1. What exists, and for how long

Three things hold finding detail. `plan/00-SPINE.md` S1 item 5 collapsed the original "8-hour buffer
file" into exactly these:

| Thing | Where | What happens at the claim timeout |
|---|---|---|
| The regenerable packet | tmpfs (`/run/anvil/...`) | Dropped (`unlink`). Not a source of truth; regenerable from the store. |
| `audit_record.payload` | the SQLite database file | Set to `NULL` by the reaper (`internal/store/schema.sql`, `audit_record.payload` comment). |
| `finding`, `finding_occurrence`, `finding_state_event`, `handoff` rows | the SQLite database file | **Never deleted.** The row moves to the `expired` literal (`record.StateExpired`, `record.HandoffStateExpired`). |

`audit_record.payload_sha256` is deliberately retained after `payload` is `NULL`ed — it is proof of what
was handed over. That is a retention decision, stated here so nobody mistakes the reaper for erasure.

The database row surviving is intentional and is the reason the timeout is safe to adopt at all:
research/08 §4.3 — *"The finding is therefore not lost; it is simply re-presented at the next scheduled
full scan or the next matching trigger. **Missing the window costs latency, not the finding.**"*

---

## 2. Anvil does not securely erase anything, and `shred` would not help

research/08 §F, quoting the coreutils manual: *"shred assumes the file system and hardware overwrite data
in place. Although this is common, many platforms operate otherwise."* [S12]

The manual then enumerates where it fails, quoted in research/08 verbatim: *"Log-structured or journaled
file systems, such as ext3/ext4 (in `data=journal` mode), Btrfs, NTFS, ReiserFS, XFS, ZFS"*; *"File
systems that write redundant data and carry on even if some writes fail, such as RAID-based file
systems"*; *"File systems that make snapshots"*; *"File systems that cache in temporary locations, such as
NFS version 3 clients"*; *"Compressed file systems"*. [S13]

On flash, research/08 quotes: *"Solid-state storage devices (SSDs) typically do wear leveling to prolong
service life, and this means writes are distributed to other blocks by the hardware, so 'overwritten'
data blocks are still present in the underlying device."* [S13]

research/08's own conclusion, which this document does not soften: *"on btrfs, ZFS, or any SSD — i.e.
essentially every modern deployment target — `shred` on the buffer file is theatre"*, and *"Any Anvil
design doc that says 'we shred the buffer at expiry' is wrong and should be corrected before it ships."*

**Therefore: no document, comment, commit message, or release note in this project may claim that Anvil
shreds, wipes, or securely deletes anything.** It does not, and adding `shred` would not make it true.

The current authority is NIST SP 800-88 Rev. 2, *Guidelines for Media Sanitization*, final 2025-09-26
[S28]; research/08 states the operational implication as *"the meaningful erase primitive for flash is
key destruction, not overwriting."* research/08 also flags, in its own Gaps section, that the full
SP 800-88 Rev. 2 PDF was not fetched and that the flash-overwrite claim rests on the coreutils manual
[S13], which it judges independent and sufficient. That caveat travels with the claim.

---

## 3. The 8-hour window is a latency bound, not a confidentiality guarantee

`plan/00-SPINE.md` S1 item 5 is binding and unambiguous: *"'8 hours' is a **claim timeout**, not a
deletion policy and not a confidentiality control."*

research/08 §A reached the same conclusion first: *"Deleting the buffer at 8 hours is **not** a
confidentiality control, because the same exploitable detail persists in the database indefinitely by
design. Treat the 8h TTL as a staleness/queue-depth control."*

And in Risks, as a named failure mode: *"**Two copies is the real security risk, and the TTL hides it.**
An 8-hour buffer TTL creates the *impression* of a short exposure window while the identical content sits
in the database indefinitely."*

Two clocks exist and are never the same clock (`internal/store/schema.sql`, `handoff` header comment):

* `handoff.lease_expires_at` — 15–30 minutes, heartbeat-renewed, governs **one** coding-agent attempt.
* `audit_record.claim_timeout_seconds` — 8 hours by default, governs how long an **unclaimed** finding
  stays eligible.

Neither is an exposure window. Neither is measured against an attacker.

---

## 4. If confidentiality-at-rest is required, this is the control

research/08 §F gives the priority order. It is not application-level deletion at any position.

1. **Keep the plaintext off persistent media entirely.** tmpfs, and since Linux 6.4 the `noswap` mount
   option disables swapping for that instance [S9]; *"If a tmpfs filesystem is unmounted, its contents
   are discarded (lost)"* [S9]. research/08 adds: *"Disable core dumps for the units, since RAM is the
   whole attack surface in this configuration."*
   **Two things research/08 could not verify, and which therefore must be checked, not assumed:** that
   `/run` is a tmpfs on every target distribution (`systemd.exec(5)` says only that `RuntimeDirectory=`
   is created below `/run/` [S29]) — mount an explicit tmpfs or check `/proc/mounts` at startup — and the
   default value of `RuntimeDirectoryMode=`, which research/08 says to set explicitly to `0700`
   regardless. Where `noswap` is unavailable, the packet can reach swap.
2. **If it must persist, encrypt the volume**, *"so that expiry can be implemented as key destruction.
   dm-crypt/LUKS via cryptsetup is GPL-2.0 (with an explicit OpenSSL-linking exception)"* [S33]. This is
   the answer to a hard requirement to prove destruction: research/08 §3 — *"SQLite row deletion +
   `secure_delete` cannot prove it on flash [S13][S15]; you would move to a per-scan LUKS2 volume [S33]
   and destroy the keyslot, which is the cryptographic-erase model NIST SP 800-88 Rev. 2 centres"* [S28].
3. **`fscrypt`** (in-kernel; ext4 / F2FS / UBIFS / CephFS) encrypts file contents, filenames and symlink
   targets, and research/08 is equally clear about its limits: it *"does not encrypt filesystem
   metadata"* — sizes, permissions, timestamps, xattrs — hole locations are unprotected, and
   `FS_IOC_REMOVE_ENCRYPTION_KEY` is not a wipe: *"Per-file keys for in-use files will *not* be removed
   or wiped"*, with decrypted cache content *"freed but not wiped"*. Use v2 policies; v1 has *"no
   verification that the provided master key is correct"* [S11]. research/08 states the residual bluntly:
   *"**`fscrypt` protects less than people assume.** ... It is not an answer to 'the buffer contained live
   exploit details and the host was compromised while running'."*
4. **`age`** (BSD-3-Clause [S32]) is fine for an encrypted archived copy but, per research/08, a poor fit
   for a concurrently mutated buffer.

None of options 1–4 is implemented by this repository. They are operator-side controls, and naming them
here is not a claim that Anvil configures them.

---

## 5. What `secure_delete` would and would not buy, and that it is not enabled

research/08 §F, quoting the SQLite pragma docs: *"Applications that wish to avoid leaving forensic traces
after content is deleted or updated should enable the secure_delete pragma prior to performing the delete
or update, or else run VACUUM after the delete or update."* [S15]

**Anvil does neither.** `internal/store/ddl.go`'s `ConnectionPragmas()` sets `journal_mode = WAL`,
`foreign_keys`, `busy_timeout`, `synchronous = NORMAL` and `wal_autocheckpoint`. `secure_delete` is not
among them, and no code in `internal/store` runs `VACUUM` after a delete. So when the reaper `NULL`s
`audit_record.payload`, the old bytes remain in the database file's freed pages.

Enabling it would not close the gap either. research/08 records both limits:

* `secure_delete=FAST` *"has the effect of purging all old content from b-tree pages, but leaving
  forensic traces on freelist pages"*, and FTS3/FTS5 virtual tables *"might leave forensic traces in
  their shadow tables even if the secure_delete pragma is enabled."* [S15] `internal/store/schema.sql`
  creates `advisory_fts` as an FTS5 virtual table, so that second limit applies to this schema directly.
* The layering, quoted from research/08: *"zeroing bytes *inside the database file* still does not erase
  the old physical flash blocks [S13] — it defends against someone reading the file, not someone reading
  the raw device."*

**Related, and separate:** what is allowed *into* durable columns in the first place is governed by
`schema.sql`'s `trg_occurrence_durable_text_cap_*` triggers and by the masking step `R.8`. Restricting
what is written is a different question from erasing what was written, and this document only answers the
second.

---

## 6. Copies this repository creates on purpose

research/08's Risks section names duplication, not deletion, as the real exposure: *"Two copies is the
real security risk, and the TTL hides it."* Two duplications are created by committed code and are listed
here so no one discovers them later:

* **Pre-migration snapshots.** `internal/store/migrate.go` writes a full `VACUUM INTO 'anvil-pre-v{N}.db'`
  copy of the database before applying a migration to a populated database, and refuses to migrate
  without one — research/07 §7 makes that snapshot the entire substitute for down migrations. Nothing in
  this repository deletes those snapshots. Each is a complete second copy of the payload and rows,
  persisting until an operator removes it — and removing it is subject to everything in section 2.
* **The tmpfs packet.** It is a second materialisation of content that is already in the store. It is
  regenerable and short-lived by design, but while it exists it is a second copy, and it is only
  RAM-resident if the operator actually mounted tmpfs, with `noswap` where available (section 4, item 1).

---

## 7. Two things not to do

* **Do not `shred` at expiry** — section 2. It would be theatre on every realistic deployment target and
  would create exactly the false impression this document exists to prevent.
* **Do not invoke `systemd-tmpfiles --purge` from Anvil's tooling, and do not point a `tmpfiles.d` rule at
  a parent directory.** research/08 Risks: *"In systemd 256, `systemd-tmpfiles --purge` invoked without a
  config file deleted users' `/home`; a user reported that 'a good portion of my home directory got
  deleted', and 256.1 changed `--purge` to require an explicit config file"* [S30, graded C — news/forum
  — with the 256.1 fix corroborating the incident]. research/08's implication, adopted verbatim as
  policy: *"if Anvil ships a `tmpfiles.d` snippet, scope it to a dedicated directory, never to a parent,
  and never invoke `--purge` from Anvil's own tooling."* Any such snippet is a backstop behind Anvil's own
  reaper, pinned to the birth-time age-by prefix (`b:8h`), because the default age-by set `abcmABM`
  includes atime and a mere reader would otherwise reset the clock [S3].

---

## 8. Claim-to-source trace

Every row is a claim made above and the research/08 location that already sourced it. Rows marked
*repo fact* are statements about this codebase, verifiable by reading the cited file; the security
consequence attached to each is itself a research/08 claim, listed alongside.

| § | Claim | Traces to |
|---|---|---|
| 0, 2 | `shred` cannot securely delete on Btrfs/ZFS/XFS/NTFS/ext3-4 `data=journal`/compressed/RAID/snapshotting FS/NFSv3 | research/08 §F [S13]; Risks "`shred` is folklore for this use case" |
| 0, 2 | On SSDs, *"'overwritten' data blocks are still present in the underlying device"* | research/08 §F and Risks [S13] |
| 0, 2 | *"shred assumes the file system and hardware overwrite data in place"* | research/08 §F [S12] |
| 2 | A design doc claiming "we shred the buffer at expiry" is wrong | research/08 Risks, verbatim |
| 2 | Flash's meaningful erase primitive is key destruction, not overwriting; NIST SP 800-88 Rev. 2 final 2025-09-26 | research/08 §F [S28]; Gaps ("full PDF not fetched") |
| 0, 3 | The 8-hour window is not a confidentiality control | `plan/00-SPINE.md` S1 item 5; research/08 §A |
| 3 | The TTL creates an *impression* of short exposure while identical content persists indefinitely | research/08 Risks, "Two copies is the real security risk" |
| 1, 3 | Two clocks: 15–30 min lease vs 8 h eligibility, never conflated | research/08 §4 ("Claim lease" / "Buffer eligibility TTL"); *repo fact*: `internal/store/schema.sql` `handoff` header |
| 1 | At expiry the row is not deleted; the finding is re-presented; *"Missing the window costs latency, not the finding"* | research/08 §4.3 |
| 1 | tmpfs packet dropped, `audit_record.payload` `NULL`ed, rows retained | *repo fact*: `internal/store/schema.sql` (`payload`, `purged_at`, `handoff` comment) |
| 0, 4 | The control for confidentiality-at-rest is a per-scan LUKS2 volume (keyslot destruction) or `fscrypt`, not application deletion | research/08 §F priority list [S33]; §3 "What would flip the decision" [S13][S15][S33][S28] |
| 4 | tmpfs contents *"are discarded (lost)"* on unmount; `noswap` needs Linux ≥ 6.4; disable core dumps | research/08 §F item 1, §B [S9] |
| 4 | `/run`-is-tmpfs and the `RuntimeDirectoryMode=` default were **not** verified; set `0700` explicitly | research/08 Gaps [S29] |
| 4 | `fscrypt` does not encrypt metadata; in-use per-file keys not wiped; cached plaintext *"freed but not wiped"*; use v2 | research/08 §F item 3 and Risks [S11] |
| 4 | `age` is a poor fit for a concurrently mutated buffer | research/08 §F item 4 [S32] |
| 5 | `secure_delete` must be set *before* the delete, or `VACUUM` after | research/08 §F [S15] |
| 5 | `secure_delete` is not enabled and no post-delete `VACUUM` runs | *repo fact*: `internal/store/ddl.go` `ConnectionPragmas()`; consequence from [S15] above |
| 5 | FTS5 shadow tables may retain forensic traces even with `secure_delete`; `FAST` leaves freelist traces | research/08 §F [S15]; *repo fact*: `advisory_fts` in `internal/store/schema.sql` |
| 5 | Zeroing inside the DB file does not erase the physical flash blocks | research/08 §F, verbatim [S13] |
| 6 | Duplication, not deletion, is the real exposure | research/08 Risks, "Two copies is the real security risk" |
| 6 | A full `VACUUM INTO 'anvil-pre-v{N}.db'` copy is written before migrating a populated database, and nothing here deletes it | *repo fact*: `internal/store/migrate.go`; consequence from the row above |
| 7 | `systemd-tmpfiles --purge` deleted a user's `/home` in systemd 256; scope snippets to a dedicated directory, never a parent | research/08 Risks [S30, credibility C] |
| 7 | Default age-by set `abcmABM` includes atime, so a reader resets the clock; pin `b:` | research/08 §B and Risks [S3] |

Source IDs `[S3] [S9] [S11] [S12] [S13] [S15] [S28] [S29] [S30] [S32] [S33]` refer to the Sources table of
`research/08-buffer-and-handoff.md`. Nothing above is sourced anywhere else, and nothing above is new.

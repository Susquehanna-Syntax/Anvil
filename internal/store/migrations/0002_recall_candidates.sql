-- 0002_recall_candidates — Lane B's candidates-per-scan metric (Phase 6, 2026-10-03).
--
-- Candidates per scan, not model size, decides whether Lane B is affordable
-- (eval/register.yaml, the candidates-per-scan row), and the plan makes it a
-- permanent per-scan metric rather than a number measured once. The control
-- plane writes it on the scan_run row of every scan.
--
-- NULL means Lane B did not run in this scan (a host scan, or a repository
-- scan whose policy or configuration left it out). 0 means it ran and its
-- rules matched nothing. The two are different statements and the column
-- keeps them apart; a negative count is refused.
--
-- Record v1 is frozen, so this is an additive, numbered migration and not an
-- edit to schema.sql: a store migrated to version 2 and a fresh one built from
-- 0001 then 0002 have the same shape.

ALTER TABLE scan_run ADD COLUMN recall_candidates INTEGER
  CONSTRAINT ck_scan_run_recall_candidates CHECK (recall_candidates IS NULL OR recall_candidates >= 0);

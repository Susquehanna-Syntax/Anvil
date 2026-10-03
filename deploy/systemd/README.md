# Anvil's systemd units

| Unit | What it is |
|---|---|
| `anvil-host-collector.service` | The read-only host package collector, one shot, under `DynamicUser=yes` and `ProtectSystem=strict`. It writes the inventory to stdout and nothing else. |
| `anvil-full-scan@.service`, `anvil-full-scan@.timer` | A weekly one-shot `anvil scan --full` of one repository, the instance name being the repository's escaped path. |

## Scanning a host

`anvil scan --host` never collects an inventory itself. It reads the collector's output with `--inventory FILE` or
`--inventory -`. The collector runs under its unit, so the inventory has to be handed from the unit to `anvil`.

**The journal is not that handoff.** The collector prints the inventory as one JSON line, a few hundred kilobytes on a
real host, and journald splits lines longer than its `LineMax=` (48K by default), so the inventory read back from the
journal is not the inventory the collector wrote.

The handoff that works, run as root, keeps the unit's confinement and pipes stdout directly:

```bash
systemd-run --quiet --pipe --wait --collect \
  --property=DynamicUser=yes --property=ProtectSystem=strict --property=ProtectHome=yes \
  --property=PrivateTmp=yes --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= \
  --property=RestrictAddressFamilies=AF_UNIX \
  /usr/lib/anvil/anvil-host-collector > /var/lib/anvil/host-inventory.json
anvil scan --host --inventory /var/lib/anvil/host-inventory.json
```

That repeats a subset of the unit's properties on the command line, so it can drift from the unit. Running the
collector under the unit itself and capturing its stdout without the journal is an open item, recorded in the plan.
As of 2026-10-03 neither path has been run on a real host: installing a unit needs root, which the development
machine's sessions do not use.

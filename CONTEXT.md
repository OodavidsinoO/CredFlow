# CredFlow

Automated Nessus credentialed scanning with strict 1-to-1 host-to-credential isolation to prevent account lockouts.

Uses session-based authentication (username/password) with X-API-Token extracted
from the Nessus Web UI's JavaScript to unlock the full REST API on
Nessus Professional.

## Language

**Target**:
A host to be scanned, defined by its IP address, a single credential pair, and its OS type.
_Avoid_: Host, endpoint, node, asset

**Credential**:
A username/password pair that authenticates to exactly one Target. Each Target has exactly one Credential.
_Avoid_: Login, account, auth

**Scan Job**:
The full lifecycle of scanning one Target: create a temporary Nessus scan, attach the Target's Credential, launch, poll for completion, export reports, then delete the scan. A Scan Job is atomic — it either completes fully or fails (with optional retry).
_Avoid_: Task, run, iteration

**Template**:
A Nessus scan policy template (e.g., "Basic Network Scan") identified by UUID. Used as the base configuration when creating each temporary scan.
_Avoid_: Policy, profile, preset

**Batch**:
A collection of Targets loaded from a single CSV file. All Targets in a Batch share the same Nessus scanner and configuration.
_Avoid_: Set, group, collection

**State**:
The persisted progress of each Target in a Batch, stored in SQLite. States are: `pending` → `running` → `completed` | `failed` (→ `pending` on retry).
_Avoid_: Status, progress-tracking

**Worker**:
A concurrent execution unit that claims one Target at a time from the State and runs its Scan Job. Multiple Workers can run in parallel within a single Batch, each claiming distinct Targets.
_Avoid_: Thread, process, runner

**Report**:
The output of a completed Scan Job: a `.nessus` file (XML vulnerability data) and a `.db` file (encrypted Nessus database). Both are saved to `./reports/` with the Target's IP and timestamp in the filename.
_Avoid_: Export, output, result

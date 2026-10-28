# Content Inspection Engine (prototype)

Scope: **controlled SCP/SFTP/FTP launcher only**. USB and browser upload paths are unchanged. No kernel driver. Direct `scp.exe`, FileZilla, WinSCP and generic browser traffic are not intercepted by this engine.

## How it works
1. `guarded-upload.ps1` resolves the source path and invokes `DlpAgent.exe --inspect-file SCP|SFTP|FTP <path>` under the caller's Windows identity.
2. The CLI requests the already-synchronized applicable policy snapshot from the local Agent on `127.0.0.1:18765/inspection-policy`.
3. `ContentInspectionEngine` checks channel, allowlisted filenames/locations, file extension, and configured `content_rules`.
4. `BLOCK` takes priority over `REPORT_ONLY`; a matched decision contains `policy_id`, `reason` and `matched_rule_ids`. The launcher reports it through the existing transfer-event bridge and aborts on `BLOCK`.
5. When inspection fails (bad regex, unsupported content, inaccessible/too-large file, missing Agent), CLI exits with code 4; launcher refuses transfer (fail-closed).

## Rules
- File-type matches are evaluated first, retaining the previous behavior.
- When no file-type match, content rules are checked. A **REGEX** rule is a .NET regex pattern (200 ms per rule); **DICTIONARY** is a comma-separated, case-insensitive list of literal terms.
- Content rule matches are **OR**, not AND: at least one active rule matches. If multiple policies match, `BLOCK` wins; otherwise `REPORT_ONLY`.
- Supported local content formats: UTF-8 text `.txt`, `.csv`, `.json`, `.log`, `.md`, `.xml`. A UTF BOM may be detected. Files over **2 MiB**, unsupported formats or binary content are rejected when content inspection is required.
- No PDF, DOCX, archives, nested structured-data parsing, magic-byte validation or content streaming yet.
- Content is read **locally by the caller**. Only filename, policy ID and matched rule IDs go through the existing transfer event flow; content bytes are not sent to PHP Server.
- Content is not inspected if an applicable file-type rule already matches. No match from configured rules means `ALLOW`.
- Policy `allowed_files` and `allowed_locations` skip both file-type and content checks. They apply only for the controlled launcher path.
- Server `content_rules` and `agent_policy.php` already supply needed fields; **no schema migration** required.

## Manual VM test
1. On `agent-test`, build and install updated Agent; keep service running with active DEVICE/GROUP policy, `CLIENT_SCP` exit point, `BLOCK` action.
2. Create a `REGEX` content rule on Server with pattern `CONFIDENTIAL-[0-9]{4}`, attach it to the policy. Leave file_types empty to test content instead of extension.
3. Make two disposable UTF-8 text files, one containing `CONFIDENTIAL-1234`, another `public notes`.
4. From PowerShell in the test VM run:
   `./agent-v2/protocol-guard/guarded-upload.ps1 -Protocol SCP -File C:\\Lab\\secret.txt -Destination user@192.168.1.50:/tmp/ -DryRun`
5. Expected: secret file => `BLOCK / CONTENT_RULE` with rule ID, exit 3; public file => `ALLOW`, exit 0 with `-DryRun`. An allowlisted secret file should be allowed. Remove `-DryRun` only for authorized lab transfers.
6. Test a malformed regex, missing policy bridge and file exceeding 2 MiB: inspection must exit 4 and launcher must refuse transfer.

## Important limitations
This does not inspect arbitrary outgoing protocols. File may change between inspection and actual transfer (TOCTOU). The launcher must be invoked voluntarily or enforced separately. Localhost policy/transfer bridges are lab interfaces and are not a trusted security boundary. Do not describe a policy verdict as proof of network-level blocking or proof of a completed report to Server.

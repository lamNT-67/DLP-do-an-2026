# USB destination preflight

USB Increment 1B diagnoses the whitelist status of an existing directory on a Windows drive. Run it from the repository with the drive root, a subdirectory, or a directory mounted to another volume.

```powershell
python -B agent/usb_preflight.py 'E:\Transfer' --config 'C:\Lab\agent.ini'
```

The optional INI is a registered lab agent configuration with `server_url`, `hostname`, and `api_token` in `[agent]`. The command reuses the policy client's `GET agent_policy.php` and the `usb_whitelist` field. Without `--config`, it collects destination metadata offline and returns `WHITELIST_UNAVAILABLE`. Python callers can pass an already-fetched response to `preflight_usb_destination(destination, policy_response)`. [Policy API contract](../../server/docs/API_CONTRACT.md#2-get-agent_policyphp)

The command prints a JSON object with `status`, `volume_id`, and `diagnostic`. The status describes the observation made during the preflight. A completed diagnostic exits with code 0 for each status.

| Status | Meaning |
|---|---|
| `LISTED` | The eligible disk has a unique, reported serial present in the whitelist. |
| `UNLISTED` | The eligible disk has a unique, reported serial absent from a valid whitelist. An empty list is valid. |
| `IDENTITY_UNKNOWN` | The available metadata cannot establish a unique eligible USB identity. |
| `WHITELIST_UNAVAILABLE` | The policy or its `usb_whitelist` data is missing or malformed. This status takes precedence when the identity also cannot be established. |

The separate diagnostic identifies collection problems such as `INVENTORY_ACCESS_DENIED`, `INVENTORY_TIMEOUT`, `INVENTORY_QUERY_FAILED`, `INVENTORY_INVALID`, `INVENTORY_CHANGED`, or `DESTINATION_CHANGED`. `IDENTITY_UNVERIFIED` covers missing, ambiguous, or unsupported device identities from a completed collection. Output includes the selected volume GUID when resolution and collection complete and omits disk paths and serials.

## How identity is collected

The preflight opens an existing directory with read-attributes access and asks Windows for the final path using a volume GUID. This lets a mounted folder resolve to the underlying volume. Disk numbers join partition records to disk records within one collection. Drive letters and other access paths serve as locators. [Directory handles](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-handle-to-a-directory) · [Final path by handle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)

One local Windows PowerShell invocation queries `Get-Disk` before and after `Get-Partition`. The PowerShell subprocess has a 15-second timeout. The adapter rejects inventories over 128 disks, 1,024 partitions, or 2 MiB of JSON. It requires a disk device interface path on an online disk reported as USB with both boot and system flags clear and retains volume claims and serials from excluded disks to detect collisions. The preflight resolves the destination again after collecting inventory and discards the result if the observed volume changed. [Get-Disk](https://learn.microsoft.com/en-us/powershell/module/storage/get-disk) · [MSFT_Partition](https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-partition)

## Standard-user privileges and limitations

Use the signed-in standard user's existing Windows session on the authorized lab VM. The command expects x64 Python and the Windows PowerShell Storage module. The account needs directory traversal and metadata access plus read access to the local Storage provider. For `--config`, it also needs read access to the registered agent INI and connectivity to the policy API. These permissions can vary with the lab image and local security policy. Permission failures are returned as diagnostics using the current account.

Device-reported serials are administrative identifiers. Windows or the USB bridge may omit, duplicate, or change them. A match establishes membership for the reported serial only. Hardware authenticity remains unverified.

After trimming surrounding whitespace, the placeholder check is limited to strings made entirely of ASCII zeros and the case-insensitive tokens `UNKNOWN` and `N/A`. A disk reporting one of these values yields `IDENTITY_UNKNOWN` with a valid whitelist, even when the whitelist contains the same placeholder. Other usable serials compare exactly after trimming, including case and leading zeros.

Devices whose Windows provider omits the GUID or interface path, exposes conflicting mappings, or reports a different bus remain unresolved. The command accepts drive-qualified directories and relies on the Windows mount manager for a local volume GUID. The GUID is scoped to the Windows host and volume lifecycle. [Windows volume names](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume) · [MSFT_Disk](https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-disk)

The Windows directory metadata calls are synchronous and run outside the subprocess timeout. Preflight gives a point-in-time result. Storage and mount changes can occur between checks or after the result. A future managed copy will need a fresh destination check at write time and its own admission and inspection decision.

## Pending lab verification

Run the command under a standard account in an authorized Windows VM with actual USB media. Confirm that the Storage provider exposes the disk interface path, reported serial, and partition GUID in that account. Compare listed and unlisted media, two volumes on one disk, a mounted folder if supported, and removal and reinsertion under a different letter. Verify rejection of an internal or system destination and confirm that every preflight leaves the test media contents unchanged. Capture the Windows and Python versions, user privilege level, command, observed status, and relevant diagnostic.

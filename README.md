# PHP Advanced Hunting

Microsoft Defender Advanced Hunting query that lists PHP installs in a tenant and shows which devices are still exposed to CVE-2026-109618 and CVE-2026-109619.

Run [`queries/php-inventory-vs-fixed.kql`](queries/php-inventory-vs-fixed.kql) in the [Microsoft Defender portal](https://security.microsoft.com) under **Hunting → Advanced hunting**. The account needs access to Defender Vulnerability Management tables.

## What it returns

One row per device that has PHP in software inventory. Each installed version is labeled:

| Status | Meaning |
|--------|---------|
| Fixed | Installed build is the fixed version for that branch, or newer. |
| Vulnerable | Branch is in the fixed-version table and the installed build is older than the fixed version. |
| Vulnerable-EOL | No fixed build is listed and the version is below 8.2.0. |
| Unknown | No fixed build is listed and the version is 8.2.0 or newer (a branch the table does not cover yet). |

A device is **Vulnerable** when any of its PHP versions are Vulnerable or Vulnerable-EOL. **Gap** is true when the device is Vulnerable and `DeviceTvmSoftwareVulnerabilities` has no row for these CVEs on that device. Sort order puts gaps first.

## Updating the baseline

The CVE list and the fixed builds are at the top of the query. The branch key is `major.minor`:

```kusto
let cves = dynamic(["CVE-2026-109618", "CVE-2026-109619"]);
let fixed = datatable(Branch:string, FixedVersion:string) [
    "8.5","8.5.12", "8.4","8.4.27", "8.3","8.3.36", "8.2","8.2.35"
];
```

Change those two blocks when the advisory or the fixed builds change.

## Tables

- `DeviceTvmSoftwareInventory` — installed software, including the PHP version
- `DeviceTvmSoftwareVulnerabilities` — TVM finding per device and CVE
- `DeviceInfo` — device type, machine group, internet-facing flag, public IP, and exposure level

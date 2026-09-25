# PyNetScan 2.2.0 — Redirect-aware device identification

This release implements the approved HTTP-identification and manufacturer-fallback changes against the GitHub 2.1.0 baseline. The application remains a single `netscan.py` file. No additional required Python packages, `curl`, or Wireshark executable are needed.

## Changes

- Retain HTTP redirect locations instead of reducing them to a status code.
- Make lightweight HTTP identification automatic in Standard and Deep; other profiles can enable it with `--banners`. Add `--no-web-identification` for an explicit opt-out.
- Follow at most three redirects per chain, eight requests per host, with a 10-second web-work budget per host plus bounded scheduling/cleanup overhead. Responses are limited to 16 KiB of headers and 64 KiB of sampled body.
- Restrict redirect connections to the original scanned IP. General hostnames must resolve exclusively to that IPv4 address. Pin the connection after resolution, preserving the advertised hostname for HTTP Host and TLS SNI.
- Recognize the documented MAC-matched Meraki local-status alias and connect to the original device even when that alias cannot be resolved. Do not mistake the advertised hostname for a configured device name or exact model.
- Keep an inferred Meraki label even if the advertised page cannot be reached. Other recognized product-title hints currently include Fortinet/FortiGate, Synology, and QNAP. Generic Login pages do not become device names.
- Preserve aliases and resolved names. Mark inferred list names with `~`; show name/vendor provenance in Details.
- Reject off-target redirects, credentials in URLs, unsafe URL syntax, loops, and HTTPS downgrades. Do not attempt logins or propagate cookies. Query values/fragments and raw bodies are not exported.
- Keep web endpoint observations separate from the original TCP probe states, even when a redirect requests a port not included in the original scan.
- Add a validated Wireshark-data fallback for failed IEEE downloads, including HTTP errors such as 418. Reject invalid/incomplete datasets and preserve existing caches. Support 24-, 28-, and 36-bit longest-prefix matching.
- Read legacy flat OUI caches and record publisher metadata in cache format 2 on new downloads. Reuse successful cached downloads for 30 days rather than repeating downloads on every scan.
- Expose database-unavailable, disabled, missing-MAC, and unmatched-assignment states separately.
- Append identity/source/web fields to CSV and JSON; retain JSON schema 2 and the existing port-state encoding. Remove stale web observations from missing-device refresh results.
- Update README, CLI help, and built-in help.

## Important behavior

HTTPS identity collection accepts unverified certificates, as the prior banner collector did. `tls_validation` explicitly says `not_verified_inventory_only`. SNI handling is not a certificate-trust check. Web/vendor identification remains inference, not authenticated identity.

Web identification sends extra read-only requests, possibly to an advertised port outside the selected port list, but never to a different IP. These requests are separate from the TCP/UDP probe-rate cap. Use `--no-web-identification` to turn them off.

The exact device model, management-system display name, and operating system may remain unknown. This change set does not add the separate DNS-queue, broad mDNS, SSDP-description, ICMP-OS, or expanded SNMP features discussed earlier.

## Verification performed

- **59 automated checks passed**, including real loopback HTTP/HTTPS fixtures, Host/SNI, same-IP restrictions, DNS pinning, redirect/memory/time limits, cancellation, alias/name preservation, manufacturer fallback/cache behavior, and JSON/CSV output.
- **Three real pseudo-terminal runs passed**: normal terminal, narrow terminal, and cancellation with partial JSON results. Standard-profile automatic web identification was exercised against a controlled loopback fixture; CSV export and detail/help navigation were checked.
- **32 README command examples passed argument parsing.** Markdown fences were checked, and CLI help was regenerated from this version.
- Python syntax compilation and Python 3.9 grammar parsing passed. Runtime checks used Python 3.13.5; other Python versions were not runtime-tested here.
- The original redirect-retention and missing-fallback checks were observed failing before the fixes.

No test requests were sent to your LAN, LXC, or physical Meraki device. Publisher failures and database contents were simulated for downloader tests. Live publisher downloads could not be verified from this execution environment because its network DNS lookup failed. Confirm fallback downloads and the physical-device response in the LXC.

No tests directory or test dependencies are shipped. GitHub has not been modified.

## Install and check in the development LXC

Transfer `PyNetScan-2.2.0-update.zip` to `/root/dev/incoming/`. It contains `netscan.py`, `README.md`, `RELEASE_NOTES_2.2.0.md`, and `SHA256SUMS` at its root.

Extract to a staging directory, review any local edits, create a development branch, and copy only the intended files into `/root/dev/PyNetScan`. Do not extract over an unreviewed modified repository.

```bash
python3 -m zipfile -e /root/dev/incoming/PyNetScan-2.2.0-update.zip /root/dev/incoming/PyNetScan-2.2.0
cd /root/dev/incoming/PyNetScan-2.2.0
sha256sum -c SHA256SUMS
```

After placing the files in the working tree:

```bash
cd /root/dev/PyNetScan
chmod +x netscan.py
python3 -m py_compile netscan.py
python3 netscan.py --version
python3 netscan.py --network 192.168.1.1/32 --profile standard --json --output /root/dev/scan-results/meraki-2.2.0.json
```

Create the output directory first if it is missing. Allow the scan to finish, then exit with `q`. The saved report distinguishes inferred vendor/name evidence, advertised endpoints, successful HTTP responses, and failures. No `--banners` option is required for Standard's HTTP identification.

## Commit message

```text
docs/feat: add redirect-aware device identification in PyNetScan 2.2.0

- Retain HTTP redirects and inspect bounded same-device endpoints
- Preserve advertised HTTP Host and TLS SNI without off-target connections
- Infer supported vendors while keeping aliases and resolved names authoritative
- Add validated manufacturer-data fallback and preserve usable caches
- Expose identity evidence, endpoint outcomes, and manufacturer lookup status
- Enable lightweight Standard/Deep web identification with an opt-out
- Update README and built-in help while preserving the standalone script
```

## Baseline and integrity

Baseline script Git blob: `cf24221fb185fa49d8c547b08bbc7bf0fb2801b3`.
Baseline README Git blob: `c1a99242ea35d31c0db329a296d0d6547b872a5f`.

New `netscan.py` SHA-256:

```text
3b39d3690697e05c0bae797ec7f62fa471d364b6e21f6b63157dc9849609d37f
```

Generated caches are local runtime data. If reverting to 2.1.0 after the manufacturer cache was upgraded to format 2, move `~/.cache/netscan/oui.json` aside before rerunning that older version.

## References

- Cisco Meraki local status page and MAC-based redirect behavior: https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Troubleshooting_and_Support/Troubleshooting/Cisco_Meraki_Local_Status_Page_Security_and_SD-WAN
- IEEE primary data: https://standards-oui.ieee.org/oui/oui.csv
- Wireshark fallback data: https://www.wireshark.org/download/automated/data/manuf.gz

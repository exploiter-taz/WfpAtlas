# WfpAtlas

### WfpAtlas maps the Windows Filtering Platform layers, callouts, providers, and filters to help understand what security products are actually hooking into.

## How it works — technically

WfpAtlas touches five Windows subsystems and stitches the output together.

**BFE — the core**

Everything starts with `FwpmEngineOpen0`, which opens a read handle to the Base Filtering Engine. Five enumeration APIs pull every registered object out of it:

```
FwpmProviderEnum0    — the registered "owners" (vendors, products)
FwpmSubLayerEnum0    — sublayers, each with a weight that controls evaluation order
FwpmCalloutEnum0     — kernel callout registrations (the actual inspection code)
FwpmFilterEnum0      — individual filter rules (what traffic to match, what to do with it)
FwpmSessionEnum0     — processes currently holding an open BFE handle
```

All documented userspace APIs from `fwpuclnt.lib`. No kernel tricks, no undocumented calls. The BFE serves this data to any local admin.

**The EDR layer table**

WfpAtlas has a hardcoded table of 23 layer GUIDs that matter from a security monitoring perspective `ALE_AUTH_CONNECT_V4`, `STREAM_V4`, `ALE_FLOW_ESTABLISHED_V4`, `DATAGRAM_DATA_V4`, `ALE_CONNECT_REDIRECT_V4` and others across connection, stream, packet, flow, and redirect categories. Each enumerated callout's `applicableLayer` GUID gets checked against this table. Match = EDR-relevant. That's the entire basis for `--edr` and the deep fingerprinting.

**Driver attribution — PSAPI**

WFP providers have names but no direct link to a kernel driver. `EnumDeviceDrivers` from `psapi.lib` returns every loaded `.sys` file. WfpAtlas does substring matching between provider names and driver filenames. If the provider is `CrowdStrikeCSAgent` and `CSAgent.sys` is loaded, that's the attribution.

**ETW correlation — TDH**

`TdhEnumerateProviders` from `tdh.lib` returns every registered ETW provider. WfpAtlas cross-references vendor name substrings against the WFP providers already found giving a combined view of what a vendor has registered across both surfaces.

**Session SID resolution — Advapi32**

Each `FWPM_SESSION0` struct contains the opener's SID. `ConvertSidToStringSidA` and `LookupAccountSidA` from `advapi32.lib` resolve it to a readable username.

**Watch mode**

`--watch` doesn't use WFP subscription callbacks it polls all five enumeration APIs in a loop, sleeps N seconds, then diffs. `[+]` for additions, `[-]` for removals. Ctrl+C sets a stop flag via `SetConsoleCtrlHandler`.

**Baseline and diff**

`--baseline` writes a plain-text snapshot of all four object types to a file one `{GUID}=name` line per object. `--diff` reads it back and compares against current state. Human-readable, no external libraries.

**Vendor fingerprint table**

50+ entries, each a name substring paired with known GUIDs for that product. Matching runs against provider names, callout names, and filter names simultaneously. `--edr-deep` groups all hits under the vendor name and pulls in driver and ETW results alongside.

---

## A practical scenario

Imagine you already obtained local administrator privileges during an engagement or even inside environments like `HTB Prolabs`.

You suspect the EDR is heavily monitoring outbound connections, loopback traffic, DNS, flow establishment, and packet-level telemetry. But you still don't know which WFP layers it's using, which providers registered the callouts, whether it's doing stream inspection or just connection telemetry, which kernel driver is behind the provider, or whether ETW telemetry is running alongside.

Instead of blindly interacting with the network stack, **WfpAtlas** helps map the terrain first.

---

## For red teamers

You already have admin. The question now is: what does the EDR actually see?

**Map the terrain before you move**

Run `--edr-deep` first. It tells you which EDR is present, which kernel driver it loaded, which WFP layers it registered callouts on, and whether it's generating ETW telemetry alongside. That's your visibility map before you touch the network.

If it has callouts on `STREAM_V4` it can see TCP payload content. If it's on `ALE_CONNECT_REDIRECT` — it's proxying your connections. If it's only on `ALE_AUTH_CONNECT` and `ALE_FLOW_ESTABLISHED` — it's doing connection telemetry, not deep inspection. Each of those has different implications for what you can and can't do undetected.

**Find the coverage gaps**

`--callouts --no-builtin` strips Windows noise and shows only third-party callouts. A product with no callout on `DATAGRAM_DATA_V4` has no WFP-level visibility into your UDP traffic. That's a data point.

`--weight-conflicts` finds sublayers sharing the same weight evaluation order between them is undefined. Clean on mature single-product machines like Elastic or Defender. Gets interesting when two EDRs are stacked, or when corporate DLP/network monitoring sits alongside a third-party endpoint product. Internal tooling rarely thinks carefully about sublayer weight uniqueness.

**Watch the EDR react**

`--watch` in a second terminal while you operate. If the EDR loads a new callout, registers a new filter, or drops and reloads a provider you see it the moment it happens. Observe self-repair behavior, understand what triggers the EDR to reconfigure its hooks, time your actions around those windows.

**Before and after**

`--baseline` before you run anything, `--diff` after. Clean answer to "what did this leave behind?" `--persistent` shows every object flagged to survive a reboot. `--sessions` tells you which processes hold an open BFE handle — worth knowing if something unexpected is sitting on the engine alongside the EDR.

---

## For blue teamers

Most WFP auditing happens reactively — something breaks, someone investigates. WfpAtlas lets you do it before that.

**Verify your coverage is actually there**

Run `--edr-deep` and confirm the product has callouts on the layers you expect. If your vendor claims stream inspection but nothing is registered on `STREAM_V4`, that's a conversation worth having with them.

**Catch unexpected objects**

`--callouts --no-builtin` shows what's registered that you didn't put there. WFP is a common persistence surface for malicious drivers too. `--persistent` narrows it to objects flagged to survive reboots — anything unrecognized there deserves attention. `--sessions` shows every process holding a BFE handle; your EDR should be there, anything else is a signal.

**Baseline your environment**

`--baseline` on a known-good machine, `--diff` against it later. Exact answer to what changed after an incident, a software install, or a periodic audit.

**Structural integrity**

`--weight-conflicts` finds sublayers at the same weight. In a well-managed environment that shouldn't happen outside of intentional design worth understanding before an attacker finds it first.

---

## Example observation while testing against Elastic Endpoint

The product appeared to focus primarily on `ALE_AUTH_CONNECT`, `ALE_FLOW_ESTABLISHED`, and `OUTBOUND_IPPACKET` connection authorization, flow tracking, and outbound packet visibility. No STREAM layer callouts, so heavy DPI probably isn't part of the picture here. Elastic Endpoint appeared to rely on WFP-based telemetry rather than stream-level inspection.

---

## Usage

```
WfpAtlas.exe [options]

Enumeration:
  --providers           Enumerate WFP providers
  --sublayers           Enumerate sublayers
  --callouts            Enumerate callouts
  --filters             Enumerate filters
  --drivers             Show driver attribution
  --etw                 Show ETW correlation
  --edr                 Show only EDR-relevant callouts
  --edr-deep            Per-vendor: callouts + filters + driver + ETW

v2.0.0:
  --watch               Live change monitor (Ctrl+C to stop)
  --watch-interval N    Poll interval in seconds (default: 2)
  --sessions            Enumerate open BFE sessions
  --baseline <file>     Save current WFP state to file
  --diff <file>         Compare current state against saved file
  --provider <f>        Drilldown by provider name or GUID substring
  --persistent          Show only objects flagged PERSISTENT
  --no-builtin          Suppress Windows built-in callouts
  --weight-conflicts    Detect sublayer weight collisions

Output:
  --json                Export as JSON (pipe-friendly, works with jq)
  --xml                 Export as XML
  -o, --out <file>      Output file for --json / --xml
  --no-color            Disable ANSI color
  -q, --quiet           Summary only
```

## Quick examples

```cmd
# Full enumeration
WfpAtlas.exe

# Quick EDR surface check
WfpAtlas.exe --edr -q

# Full per-vendor EDR fingerprint
WfpAtlas.exe --edr-deep

# Who has open BFE handles right now
WfpAtlas.exe --sessions

# Watch WFP change live
WfpAtlas.exe --watch --watch-interval 3

# Snapshot before install, diff after
WfpAtlas.exe --baseline clean.wfp
WfpAtlas.exe --diff clean.wfp

# Focus on one vendor
WfpAtlas.exe --provider crowdstrike
WfpAtlas.exe --provider defender

# Callouts without the Windows noise
WfpAtlas.exe --callouts --no-builtin

# Sublayer weight analysis
WfpAtlas.exe --weight-conflicts

# What survives a reboot
WfpAtlas.exe --persistent

# JSON, pipe to jq
WfpAtlas.exe --edr-deep --json | jq .edr_deep
WfpAtlas.exe --json -o full.json
```

## Build

```cmd
cl.exe /W4 /O2 /MT WfpAtlas.c /link fwpuclnt.lib ole32.lib psapi.lib tdh.lib advapi32.lib
```

Or with CMake:

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## Requirements

- Windows 10 / 11
- Administrator privileges
- MSVC (Visual Studio Build Tools)

## Planned

- [ ] graph visualization of provider → sublayer → callout relationships
- [ ] SIGMA rule output from detected EDR stack
- [ ] NDIS lightweight filter driver enumeration alongside WFP

## Final thoughts

One thing I enjoy about Windows internals:

the deeper you go, the more you realize that visibility itself is often more important than interaction.

Sometimes simply understanding the topology gives you more value than touching anything.

---

Author: taz

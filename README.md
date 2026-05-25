# WfpAtlas

### WfpAtlas maps the Windows Filtering Platform layers, callouts, providers, and filters to help understand what security products are actually hooking into.

## How it works

WfpAtlas opens a handle to the BFE (Base Filtering Engine) via `FwpmEngineOpen0`
and enumerates all registered objects using the standard WFP management APIs:

- `FwpmProviderEnum0` => registered providers
- `FwpmSubLayerEnum0` => sublayers
- `FwpmCalloutEnum0`  => kernel callout registrations
- `FwpmFilterEnum0`   => individual filter rules

Callouts are then matched against a built-in table of EDR-relevant layers
to identify which interception surfaces are active.

## A practical scenario

Imagine you already obtained local administrator privileges during an engagement or even inside environments like `HTB Prolabs`.

You suspect the EDR is heavily monitoring:

* outbound connections
* loopback traffic
* DNS
* flow establishment
* packet-level telemetry

But you still don't know:

* which WFP layers are being used
* which providers registered the callouts
* where inspection happens
* whether the product focuses on stream inspection, packet inspection, or connection telemetry

Instead of blindly interacting with the network stack, **WfpAtlas** helps map the terrain first.

## Current capabilities

* Enumerates WFP providers
* Enumerates sublayers
* Enumerates callouts
* Enumerates filters
* Maps callouts to EDR-relevant layers
* Identifies interception surfaces commonly used by EDRs
* Exports findings into XML for easier review

## Example observation while testing against Elastic Endpoint

The product appeared to focus primarily on:

* `ALE_AUTH_CONNECT`
* `ALE_FLOW_ESTABLISHED`
* `OUTBOUND_IPPACKET`

connection authorization monitoring, flow tracking, outbound packet visibility and loopback observation. no STREAM layer callouts either, so heavy DPI probably isn't part of the picture here.

Elastic Endpoint appeared to rely partially on WFP-based telemetry rather than heavy stream-level inspection.

## Why this matters

This kind of reconnaissance becomes extremely useful before:

* experimenting with WFP
* modifying filters
* analyzing network telemetry paths
* studying EDR behavior
* performing low-level Windows networking research

## Build
```
cl.exe /W4 WfpAtlas.c /link fwpuclnt.lib ole32.lib
```

## Requirements

- Windows 10 / 11
- Administrator privileges
- MSVC (Visual Studio Build Tools)

## Planned improvements

- [ ] driver attribution
- [ ] ETW correlation
- [ ] graph visualization
- [ ] provider fingerprinting

## Final thoughts

One thing I enjoy about Windows internals:

the deeper you go, the more you realize that visibility itself is often more important than interaction.

Sometimes simply understanding the topology gives you more value than touching anything.

---

Author: taz

# Internet-Exposed RCE Surface Tracker

A working checklist for the software panels that are measurably exposed on the
public internet and have a known or documented remote code execution path.

**Live page:** <https://blackfriday-netizen.github.io/rce-surface-tracker/>

## What it is

A cross-reference of two measurements of the same population, kept in one table
so the per-engine counts and the merged census sit side by side:

| Source | What it contributes |
|---|---|
| `data/unified-netlas-zoomeye-rce-surfaces.json` | The curated list: 47 distinct products with a **Netlas** count and a **ZoomEye** count each, plus analyst notes. |
| `Zoomeye-Global-Discovery/data/rce-surface-final.json` | The merged census: 105 measured entries with a merged population, **tier**, **class**, RCE-path description, CVEs, confidence and how the population was measured. |

Rows are joined on an explicit alias table (`tools/build_rce_tracker.py`), not
on fuzzy substring matching. 25 products appear in both sources and carry both
sets of numbers.

**127 rows total** — 47 from the curated list, 105 from the census, 25 in both.
Every row carries a ZoomEye figure; every row carries a merged figure.

## Reading the columns

* **ZoomEye** — the raw ZoomEye index count for the fingerprint that was
  measured: `product=`, `title=`, `app=`, `http.body=` or
  `http.header.server=`. Hover the number in the page for the **exact query**
  and the date it was measured — the query was recovered from the ZoomEye API
  credit ledger, so every figure can be reproduced instead of taken on trust.
  This is the number of hosts the index says carry the product, with **no**
  version or configuration condition applied.
* **Netlas** — per-engine measured population from the curated list. A dash
  means the product was not queried on that engine or the result was too low
  to be meaningful. It does **not** mean zero.
* **Merged** — the *affected* population: the census figure, or a
  probe-verified figure where the index fingerprint was wrong (Nagios) or the
  exposure needed a version/configuration condition (nginx). It is *not* the
  sum of the two engine columns — the engines crawl different corpora and
  overlap — and it can be much smaller than the raw index count when a
  condition was applied.
* **Tier** — how the code execution happens.
  * **T1** the product's own admin plane executes code (file manager, task
    queue, CI runner, container run, configuration script)
  * **T2** a device's management plane executes code (diagnostics, terminal,
    config import, firmware upload, CWMP/TR-069, CGI handler)
  * **T3** web/CGI stack — code execution is a configuration outcome, not a
    built-in feature
  * **T4** not an RCE surface (CDN edge, WAF, generic proxy, load balancer)
* **Class** — product family: panel, cicd, cms, automation, storage, network,
  monitoring, database, gateway, media, support, webmail, generic.
* **Window** — the takeover window, i.e. how much of an unauthenticated
  takeover is possible and what stands in the way.
  * **claim** the first network visitor can take ownership, no prior secret
  * **default** a well-known default credential, but no takeover window
  * **secret** a token or root secret that is printed or stored out of band
* **RCE path** — how code execution is reached.
* **CVE** — links to the NVD entry for the cited identifier.
* **Notes** — your own working notes for that product.

## Using it as a checklist

* **Checkbox** per row marks a product as reviewed. The row tints green and the
  progress bar in the header advances.
* **Notes box** per row is free text — what you validated, which port, what
  the RCE path turned out to be, what you ruled out.
* **Show** filters to All / Not reviewed / Reviewed / Has notes / **Actionable**
  (tier-1 products that also have a takeover window or a known CVE — 35 rows).
* **Search** matches product name, class, tier, RCE path, CVE, aliases and
  notes. Multiple words are ANDed.
* **Sort** defaults to *Priority (tier, then size)*, which puts the actionable
  tier-1 products first instead of the generic web servers.

### Where the state lives

**Two places.**

**1. This browser.** Checkboxes and notes are stored in `localStorage` and are
never transmitted anywhere. This survives a browser restart — verified with a
real persistent browser profile: full browser shutdown, relaunch, state
intact (checks, notes, row tint, header counter, progress bar).

**2. Optionally, a GitHub repository.** Open **Save & sync**, paste a token,
and the state is also pushed to a file in a repo. That copy survives a new
browser, a new device, cleared site data, and a private window. It is the
only way to move your progress between machines.

> **The token.** It is kept in this browser's `localStorage` and is sent only
> to `api.github.com`. It is never written into the page or the repository.
> Use a token scoped to the state repository alone, and revoke it from GitHub
> settings when you are done. The default target,
> `blackfriday-netizen/rce-surface-tracker-state`, is a **private** repo, so
> your notes are not published.

**Merging.** Every entry carries a timestamp. When the page pulls, each key is
taken from whichever side has the newer timestamp, so two devices working on
different products do not clobber each other, and a note you edited on one
device is not reverted by another device's stale copy. A push that loses a
race (HTTP 409) re-reads the blob SHA and retries once.

**Export / Import** moves a snapshot between browsers without any token.

Because the state is local by default, a snapshot is the only way to share
progress or keep a record of it unless sync is enabled.

## Data provenance

Rebuild the page data with:

```sh
python3 tools/build_rce_tracker.py
```

This writes `data.json` (machine-readable) and `data.js` (the same content as
a plain script, so the page also works when opened directly from disk, where
`fetch()` of a local file is blocked).

Every API call behind these numbers is logged in the workspace ledger
`Zoomeye-Global-Discovery/data/zoomeye-api-ledger.json`.

## Files

| File | Purpose |
|---|---|
| `index.html` | Page structure |
| `style.css` | Styles, light and dark |
| `app.js` | Rendering, filtering, sorting, local state, export/import |
| `sync.js` | GitHub-backed sync: the Contents API client and the merge policy |
| `data.js` | The dataset, as a plain script (works offline, from `file://`) |
| `data.json` | The same dataset, as JSON |

## What is and is not in here

**In:** product names, population counts, class and tier classification,
RCE-path descriptions, and public CVE identifiers.

**Not in:** host addresses, credentials, customer data, or any target list.

The one credential-shaped string in the data is `admin/admin` for Grafana,
which is that product's own documented first-run default and is public vendor
documentation — it is not a credential to any target.

**Your notes are not published either.** They live in your browser's
`localStorage` and, if you enable sync, in a **private** repository. The
public page contains only the aggregate measurements.

## Caveats

* Counts are platform-specific. The engines crawl different corpora, index on
  different signals, and the same product measured two ways will not agree.
  Treat these as order-of-magnitude sizing for prioritisation, not as a census.
* A population figure counts matches for a label, not necessarily live
  deployments of that product. Where a title match was verified as unrelated
  sites, the row is flagged **noise**.
* Presence of a population says nothing about whether the instance is
  vulnerable, patched, or behind a compensating control.
* A product appearing here means it is exposed and has a code-execution path.
  It does not mean any particular instance is exploitable.

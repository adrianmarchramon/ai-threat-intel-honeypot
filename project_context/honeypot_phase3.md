# Phase 3 — Enrichment: Adding Context to Attacks

> In this phase, you begin to turn your data into real threat intelligence. After the previous phase, you have structured attack sessions, each associated with the attacker's IP. But an IP, on its own, is just a number: it tells you very little. The guiding principle of this phase is that **context is what turns raw data into intelligence**. Knowing that "an IP did X" has little value; knowing that "an IP from such-and-such country, already known for malicious activity, hosted on this type of network, did X" is actionable threat intelligence. Your job here is to add that context to each attack by cross-referencing IPs with external geolocation and reputation sources.

**Phase Objective:** Turn raw attack data into threat intelligence data by adding context.  
**Duration:** Weeks 3–4.  
**Upon completion, you will have:** Attack sessions enriched with their geolocation (where they come from), reputation (whether they are known malicious IPs), and network context, so that each attack stops being an anonymous IP and becomes a contextualized threat.

---

## The Big Picture

The workflow of this phase adds context to the sessions you structured:

```
   Structured sessions (Phase 2) → Attacker IPs
        │
        ▼
   [ Unique IPs ]  ──►  deduplicate (key rule: each IP is queried ONCE)
        │
        ├──► Geolocation (GeoLite2)  → country, city, coordinates
        ├──► Reputation (AbuseIPDB)   → Is it a known malicious IP? (0-100)
        └──► Network context (Reverse DNS, ASN) → what type of network?
        │
        ▼
   [ Merge context with sessions ]  ──►  enriched attacks
```

Add the dependencies:

```bash
uv add geoip2 requests
```

---

## Step 1 — Why Enrich

Before writing code, it is useful to understand what each type of context provides, as they represent three different lenses on the same attack. **Geolocation** answers the "where": which country and region each attack comes from. This is valuable because attack campaigns are often geographically concentrated, and mapping the sources reveals patterns. **Reputation** answers the "who": has this IP already been reported by others as malicious? An IP with a known bad reputation points to an established attacker rather than a casual hobbyist. Finally, **network context** (the reverse DNS and the Autonomous System to which the IP belongs) answers "from what type of infrastructure": is it a server from a cloud provider (typical of automated attacks), a compromised residential router (typical of botnets), or a Tor node? Each answer tells you something about the nature of the attacker.

Together, these three lenses transform a list of anonymous IPs into a profile of who is attacking you and from where, which is the raw material of threat intelligence. That is why this phase, although technically simple, is the one that makes the conceptual leap from "data" to "intelligence."

---

## Step 2 — Geolocation

To geolocate IPs, the industry standard is MaxMind's **GeoLite2** database, which is free and can be used offline via the `geoip2` library. There is an access detail worth keeping in mind because it catches many people off guard: **MaxMind requires a free account and a "license key"** to download GeoLite2 databases. Therefore, the first step is to register (for free) on MaxMind, get the key, and download the `GeoLite2-City.mmdb` file. Once you have it, usage is straightforward. Complete `src/enrichment/enrich.py`:

```python
import geoip2.database
import geoip2.errors


class GeoIPEnricher:
    def __init__(self, db_path):
        # The reader is expensive to create: it is built once and reused.
        self.reader = geoip2.database.Reader(str(db_path))

    def lookup(self, ip: str) -> dict:
        try:
            r = self.reader.city(ip)
            return {
                "country": r.country.iso_code,
                "city": r.city.name,
                "latitude": r.location.latitude,
                "longitude": r.location.longitude,
            }
        except geoip2.errors.AddressNotFoundError:
            return {"country": None, "city": None, "latitude": None, "longitude": None}
```

Two design decisions were made here. First, we use the **local database** (the `.mmdb` file) instead of a geolocation API because, when processing many IPs, an offline database is faster and has no query limits. Second, **we reuse the reader** (creating it once in the constructor, not on every query) because initialization is expensive, as the official documentation warns. Notice also that we handle cases where an IP is not found in the database (`AddressNotFoundError`) by returning empty values instead of breaking execution. 

As an alternative that does not require an account, you can use `ip-api.com`, which is a free API that does not require a key (though it enforces rate limits). This is a helpful alternative if you want to avoid registering with MaxMind.

---

## Step 3 — Reputation: Is it a Known Malicious IP?

To find out if an IP is already known for malicious activity, you will use **AbuseIPDB**, a service that maintains a collaborative database of reported IPs. Its free API allows 1,000 queries per day (after registering and obtaining a key), and its check endpoint returns an **abuse confidence score** (`abuseConfidenceScore`, from 0 to 100) for an IP, summarizing how malicious it is considered based on accumulated reports:

```python
import requests


def check_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=10,
        )
        data = resp.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
        }
    except requests.RequestException:
        return {"abuse_score": None, "total_reports": None, "isp": None, "usage_type": None}
```

In addition to the abuse score, the response provides highly useful data: the number of reports, the Internet Service Provider (ISP), and the usage type (`usageType`, which distinguishes, for example, a data center from a residential connection). It is best practice to read the API key from an environment variable (`os.getenv("ABUSEIPDB_KEY")`) rather than hardcoding it into the codebase.

---

## Step 4 — Network Context

The third lens is network context, which helps to understand the type of infrastructure each IP is attacking from. **Reverse DNS** attempts to resolve the hostname associated with the IP (which sometimes reveals the provider or the host type) and is straightforward to implement using the standard library:

```python
import socket


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
```

You can obtain the **Autonomous System** (ASN) and its organization (which indicates which network the IP belongs to) from MaxMind's GeoLite2-ASN database, similarly to how you handled geolocation (using `reader.asn(ip)`). The usage type returned by AbuseIPDB also contributes to this information. With this, you know whether an attack comes from a major cloud provider, a domestic connection, or a suspicious network, helping to characterize the threat.

---

## Step 5 — The Enrichment Pipeline

This is where engineering judgment makes a significant difference: **deduplication**. Your sessions may contain the same IP address multiple times (an insistent attacker generates many sessions), but the context of an IP is always the same. More importantly, AbuseIPDB has a free limit of 1,000 queries per day. Therefore, it is essential to **query each unique IP only once** and reuse the result, instead of querying for each session. You enrich the list of unique IPs, and then merge that context back into the sessions:

```python
import pandas as pd


def enrich_unique_ips(unique_ips, geo: GeoIPEnricher, api_key: str) -> pd.DataFrame:
    """Enriches each unique IP ONLY once (critical due to API limits)."""
    rows = []
    for ip in unique_ips:
        rows.append({
            "src_ip": ip,
            **geo.lookup(ip),
            **check_abuseipdb(ip, api_key),
            "rdns": reverse_dns(ip),
        })
    return pd.DataFrame(rows)


def enrich_sessions(sessions: pd.DataFrame, geo: GeoIPEnricher, api_key: str) -> pd.DataFrame:
    unique_ips = sessions["src_ip"].dropna().unique()
    context = enrich_unique_ips(unique_ips, geo, api_key)
    return sessions.merge(context, on="src_ip", how="left")
```

This deduplication is crucial: it is what makes enrichment viable and respectful of external API limits. If your honeypot records 5,000 sessions from 800 distinct IPs, you query 800 times instead of 5,000, staying well within the free limit. For a project designed to run continuously, it is worth going a step further and **caching** results persistently (saving already-queried IPs to disk) so you don't re-query an IP tomorrow that you already looked up today. This detail demonstrates planning for a system working in a real production environment rather than a one-off run.

The module's `main` block loads the sessions from the previous phase, enriches them, and saves the result:

```python
if __name__ == "__main__":
    import os
    from src.config import GEOIP_DB

    sessions = pd.read_parquet("data/sessions.parquet")
    geo = GeoIPEnricher(GEOIP_DB)
    enriched = enrich_sessions(sessions, geo, os.getenv("ABUSEIPDB_KEY"))
    enriched.to_parquet("data/sessions_enriched.parquet")
    print(enriched[["src_ip", "country", "abuse_score", "usage_type"]].head())
```

---

## Step 6 — Testing

Since enrichment relies on external services (the MaxMind database, the AbuseIPDB API), the most valuable aspect to test without these external dependencies is the **deduplication** logic, which is the core of this phase. You can verify it using a mocked lookup function that counts calls. Complete `tests/test_enrichment.py`:

```python
import pandas as pd

from src.enrichment.enrich import enrich_sessions


def test_deduplicates_queries(monkeypatch):
    # Sessions with repeated IPs: 4 sessions, but only 2 unique IPs
    sessions = pd.DataFrame({
        "session": ["a", "b", "c", "d"],
        "src_ip": ["1.1.1.1", "1.1.1.1", "2.2.2.2", "1.1.1.1"],
    })

    calls = {"n": 0}

    class MockGeo:
        def lookup(self, ip):
            calls["n"] += 1
            return {"country": "XX", "city": None, "latitude": None, "longitude": None}

    # Avoid making real calls to AbuseIPDB and DNS
    monkeypatch.setattr("src.enrichment.enrich.check_abuseipdb",
                        lambda ip, key, **kw: {"abuse_score": 0})
    monkeypatch.setattr("src.enrichment.enrich.reverse_dns", lambda ip: None)

    result = enrich_sessions(sessions, MockGeo(), api_key="x")

    # Each unique IP is queried ONCE: 2 IPs → 2 calls, not 4
    assert calls["n"] == 2
    # But the context is merged back into all 4 sessions
    assert len(result) == 4
    assert result["country"].notna().all()
```

This test checks the main logic of this phase: that each unique IP is queried only once (deduplication), yet the context propagates to all corresponding sessions. This logic is precisely what keeps enrichment within API limits. Run it with `make test`.

---

## Verification: The "Definition of Done"

The phase is complete when the following are met:

- [ ] Source IPs are geolocated (country, and optionally city and coordinates).
- [ ] IPs are cross-referenced with a reputation source (the AbuseIPDB abuse score).
- [ ] Network context is added (reverse DNS, usage type, or ASN).
- [ ] Enrichment deduplicates queries (each unique IP is queried once), respecting API limits.
- [ ] The context is merged back into the sessions.
- [ ] **The key test:** each attack is no longer just "an IP did X", but "an IP from country Y, known (or not) for malicious activity, did X".

The key test is the leap from data to intelligence: if you can look at any attack and describe it not as an anonymous IP, but with its origin, reputation, and network type, you have turned your data into threat intelligence. This context is what distinguishes a raw log dump from actual threat analysis, and it is the foundation that will make the analysis in the upcoming phases meaningful.

---

## Deliverables and What's Next

Upon closing Phase 3, you have enriched attack sessions: each one is no longer an anonymous IP, but a threat with context (where it comes from, what its reputation is, and what type of network it operates from). You have made the conceptual leap from "attack data" to "threat intelligence data" and resolved the engineering challenge of doing so efficiently and respectfully of API limits by deduplicating queries. You now have a rich, contextualized dataset ready for in-depth analysis.

The next step, **Phase 4**, begins extracting patterns at scale using **classical machine learning**. With structured and enriched attacks, you will use unsupervised machine learning to group similar attack sessions (discovering campaigns and common patterns), classify attack types, and detect anomalous sessions that deserve special attention, leveraging the ML workflows you have established. You have gone from having attacks with context to being on the verge of finding the patterns hidden within thousands of attacks.

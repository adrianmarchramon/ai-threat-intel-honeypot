# Roadmap: Honeypot with AI-Powered Threat Analysis

> A system that deploys a decoy on the internet to attract real attackers, captures everything they do, and uses AI to turn that flood of logs into actionable **threat intelligence**: who is attacking you, from where, with what techniques, and with what intent. It combines two of the most in-demand fields today—**cybersecurity** and **AI**—and features an ingredient that almost no portfolio project can offer: it works with **real attack data**, not a toy dataset.

**Estimated Duration:** 8–10 weeks (part-time)
**Level:** Intermediate-Advanced
**Final Result:** A securely deployed honeypot that captures real attacks, a pipeline that structures and enriches this data, analysis using classical ML (clustering, classification, anomaly detection) and a local LLM (summarization, intent inference, mapping to MITRE ATT&CK), and a threat intelligence dashboard to present it all.

> **Safety and Legal Note (from the start):** A honeypot attracts real attackers, so operating one carries real risks that must be taken seriously. It must be **completely isolated** from any production systems, must not be capable of being used as a launchpad to attack third parties, and you must **never** "attack back" (which constitutes unauthorized access and is illegal regardless of intent). There are also legal nuances (for example, regarding data capture). Approaching this with rigor is not a mere formality: it is part of what demonstrates maturity in a security project, just as the disclaimer did in the medical project.

---

## 1. What Exactly You Will Build

A system that goes from decoy to intelligence, following this workflow:

```
   Internet (real attackers)
        │
        ▼
   [ Honeypot (Cowrie) ]  ──►  isolated decoy that captures every action of the attacker
        │  (JSON logs)
        ▼
   [ Ingestion & Structuring ]  ──►  sessions, commands, IPs, credentials, payloads
        │
        ▼
   [ Enrichment ]  ──►  geolocation, threat intelligence (known malicious IP?)
        │
        ▼
   [ Analysis ]
        ├── Classical ML  → cluster similar attacks, classify them, detect anomalies
        └── Local LLM     → summarize sessions, explain intent, map to MITRE ATT&CK
        │
        ▼
   [ Threat Intelligence Dashboard ]  ──►  map, patterns, techniques, reports
```

The core idea, and what truly brings value to the project, is this: **capturing attacks is the easy part** (the honeypot does it automatically once exposed to the internet); the difficult and valuable part is **converting the flood of raw logs into actionable intelligence**. A honeypot can generate tens of thousands of events in just a few days, making manual analysis impossible. That is where AI comes in: to parse, group, summarize, and make sense of all that data at scale. A honeypot is only as valuable as your ability to analyze what it captures, and that capability is exactly what you are building here.

---

## 2. The Use Case and Why It Stands Out

The project addresses a real security problem: understanding the threats that are actually out there. It combines several aspects that make it particularly powerful for your portfolio.

**Works with real data, not toy datasets.** This is perhaps its greatest advantage. The vast majority of portfolio projects use overused public datasets; yours captures **real attacks** occurring against your decoy on the internet. Being able to say, "I analyzed thousands of real attacks against my honeypot, originating from these regions, using these techniques," has an impact that no Kaggle dataset can match. Additionally, it solves a known challenge: real attack data is scarce and proprietary, and a honeypot is one of the few ways to legitimately obtain it.

**Combines cybersecurity and AI, two highly in-demand fields.** Cybersecurity on its own is a sector with massive demand; so is AI. A project that unites them (a honeypot whose data you analyze with AI) demonstrates an uncommon and highly valuable profile, sitting right at the intersection that connects to your interest in security.

**Produces concrete threat intelligence.** The output is not abstract: it is actionable intelligence (who is attacking, from where, using which techniques, mapped to a standard framework like MITRE ATT&CK). This is exactly the kind of work real security teams perform.

**Applies AI to a genuine problem.** The AI analysis is not decorative: it solves the very real problem of honeypots generating overwhelming volumes of logs. Using ML to find patterns at scale and an LLM to summarize and contextualize is an authentic, modern application of AI to security.

Furthermore, this project connects naturally to your previous ones: it repurposes the data and ML rigor from the MLOps project, along with the entire **local LLM stack using Ollama** from the RAG project (which is highly recommended here for cost and privacy reasons, as analyzing a public honeypot with a commercial API would incur costs for every attacker command). And, like the medical project, it carries a dimension of responsibility (security and compliance) that demonstrates maturity.

---

## 3. Technology Stack (Updated to 2026)

| Layer | Tool | Why This One |
|------|-------------|--------------|
| Honeypot | **Cowrie** | The community standard for SSH/Telnet; medium interaction, logs every command, outputs in JSON |
| Deployment/Isolation | Cheap VPS + **Docker** + firewall | Expose the decoy to the internet in an isolated, controlled manner |
| Language | Python 3.11+ with **uv** | Standard; reuse your baseline from previous projects |
| Ingestion | Python + **pandas** | Parse and structure Cowrie's JSON logs |
| Enrichment | **GeoIP** (GeoLite2) + threat intelligence (e.g., AbuseIPDB) | Geolocate attacks and cross-reference them with known malicious IPs |
| ML | **scikit-learn** | Clustering, classification, and anomaly detection of attacks |
| LLM | **Ollama** (local model) | Summarize sessions, explain intent, map to MITRE ATT&CK, with zero cost and no data leaks |
| Threat Framework | **MITRE ATT&CK** | Classify attacker techniques using the industry standard |
| Dashboard | **Streamlit** | Present intelligence (map, patterns, reports) with minimal code |
| Quality | pytest, ruff, Docker | Reutilize practices from your previous projects |

A few notes on these choices, as the reasoning behind them demonstrates strong decision-making:

**Cowrie as a honeypot.** It is the community standard for SSH and Telnet honeypots and is ideal for this project. It is *medium-interaction*: rather than a simple decoy that only logs connections, it simulates a convincing Linux shell with a mock file system, logging every command the intruder types, their credential attempts, and the files they try to download. This provides you with rich, structured data (in JSON) for analysis. As alternatives, **T-Pot** (by Deutsche Telekom) is a comprehensive platform combining over 20 honeypots but is much heavier; and **Beelzebub** is a honeypot that uses an LLM to generate dynamic responses—an advanced option you can reserve as a future enhancement.

**Isolation as a requirement, not an option.** The honeypot must be deployed in a completely isolated environment (a cheap, dedicated VPS is typical), containerized, and configured with a firewall that prevents the decoy from accessing anything real or being used to attack third parties. This is a core part of the design, not an afterthought.

**The local LLM with Ollama.** You reuse everything learned in the RAG project, and there are two compelling reasons to keep it local: **cost** (analyzing each of the thousands of captured commands with a commercial API would quickly become expensive, whereas a local model is free) and the consistency of running continuous, on-premises analysis. The LLM handles the "intelligent" part of the process: translating an attack session into a readable explanation, inferring what the attacker was looking for, and mapping their actions to MITRE ATT&CK techniques.

**MITRE ATT&CK.** This is the industry-standard framework for describing adversary techniques. Mapping attacks to ATT&CK transforms your analysis into something any security professional will recognize and value, showing that you speak the industry's language.

---

## 4. Repository Architecture

```
honeypot-ai-threat-intel/
├── src/
│   ├── ingestion/
│   │   └── parse_logs.py      # parse Cowrie JSON logs into structures
│   ├── enrichment/
│   │   └── enrich.py          # geolocation + threat intelligence
│   ├── analysis/
│   │   ├── ml.py              # clustering, classification, anomalies
│   │   └── llm.py             # LLM analysis (summary, intent, MITRE)
│   └── config.py
├── dashboard/
│   └── app.py                 # threat intelligence dashboard
├── honeypot/
│   ├── docker-compose.yml     # isolated Cowrie deployment
│   └── cowrie.cfg             # honeypot configuration
├── data/                      # captured logs (gitignored)
├── docs/
│   ├── context.md             # the problem, threat intelligence
│   └── legal_safety.md        # legal, ethical, and safety considerations
├── tests/
├── notebooks/
├── pyproject.toml
├── Makefile
└── README.md
```

The structure mirrors the workflow of the project: `ingestion` (parsing the logs), `enrichment` (adding context), `analysis` (ML and LLM, separated), the `dashboard` in its own folder, and a `honeypot` folder for the decoy's configuration and deployment. The `docs/legal_safety.md` file stands out: in a security project, documenting legal and safety considerations is as important as the code itself, and having it in place communicates that you take this dimension seriously.

---

## 5. Phase-by-Phase Roadmap

Each phase has an objective, tasks, a deliverable, and a definition of "done".

---

### 🔹 Phase 0 — Setup, Foundations, and Safety (Week 1, initial days)

**Objective:** Environment ready, understanding honeypots and threat intelligence, and establishing a clear legal and safety framework.

**Tasks:**
- [ ] Create the repo structure, set up the environment with `uv`, code quality checks, and Makefile (reusing patterns from previous projects).
- [ ] Understand what a honeypot is, its types (low/medium/high interaction), and what threat intelligence entails.
- [ ] Document the legal, ethical, and safety framework (isolation, no attacking back, legal nuances of data capture).
- [ ] Plan the isolated deployment (which VPS, how to isolate it).

**Deliverable:** Ready environment + understanding of honeypots + documented safety framework.
**Definition of Done:** You understand what you will deploy and why, and you have clear, documented safety and legal precautions.

---

### 🔹 Phase 1 — Securely Deploying the Honeypot (Weeks 1–2)

**Objective:** Have an operational honeypot capturing real attacks in an isolated environment.

**Tasks:**
- [ ] Deploy Cowrie (containerized) on an isolated VPS.
- [ ] Configure it (fake shell, mock file system, JSON logging).
- [ ] Secure the isolation (firewall, no access to production systems, no possibility of being used as a stepping stone).
- [ ] Expose it and start capturing data.

**Deliverable:** A functioning, isolated honeypot capturing real attacks.
**Definition of Done:** The honeypot is online, logging attacks in JSON, and you have verified its isolation. (In just a few days you will start seeing real attacks, which is exciting.)

---

### 🔹 Phase 2 — Log Ingestion and Structuring (Weeks 2–3)

**Objective:** Convert raw logs into structured, analyzable data.

**Tasks:**
- [ ] Write `parse_logs.py` to read Cowrie's JSON logs.
- [ ] Structure key information: sessions, source IPs, executed commands, attempted credentials, downloaded files.
- [ ] Build a robust ingestion pipeline (with the data rigor learned in MLOps).
- [ ] Handle high volumes of data (as there can be a very high number of events).

**Deliverable:** A pipeline that converts Cowrie logs into structured data.
**Definition of Done:** You have the captured attacks in a structured, clean format ready for enrichment and analysis.

---

### 🔹 Phase 3 — Enrichment: Contextualizing the Attacks (Weeks 3–4)

**Objective:** Turn attack data into threat intelligence by adding context.

**Tasks:**
- [ ] Geolocate the source IPs (where the attacks come from) using GeoIP.
- [ ] Cross-reference IPs with threat intelligence feeds (is it a known malicious IP? e.g., with AbuseIPDB).
- [ ] Add other useful contexts (reverse DNS, network type, etc.).

**Deliverable:** Attack data enriched with threat intelligence context.
**Definition of Done:** Every attack is no longer just "IP address did X," but rather "an IP from this country, known (or unknown) for malicious activity, performed X."

---

### 🔹 Phase 4 — Analysis with Classical ML (Weeks 4–5)

**Objective:** Find patterns in the attacks at scale.

**Tasks:**
- [ ] Write `ml.py` using unsupervised analysis: **cluster** similar attack sessions to discover campaigns or common patterns.
- [ ] **Classify** the attack types (brute force, scanning, malware installation attempts, etc.).
- [ ] **Detect anomalies**: unusual sessions that warrant special attention.
- [ ] Extract useful metrics (most attempted credentials, most common commands, etc.).

**Deliverable:** An ML analysis that uncovers attack patterns.
**Definition of Done:** You can display the predominant attack clusters, types, and anomalies based on real-world data.

---

### 🔹 Phase 5 — LLM Analysis: Threat Intelligence (Weeks 5–7)

**Objective:** Convert raw attack sessions into readable intelligence. **This is the AI component that makes the project stand out the most.**

**Tasks:**
- [ ] Write `llm.py` using a local LLM (Ollama) to **summarize** an attack session in plain language ("this attacker tried X, then Y").
- [ ] Infer the attacker's **intent** (what were they looking for? installing a miner? recruiting for a botnet?).
- [ ] **Map** the actions to **MITRE ATT&CK** techniques.
- [ ] Generate readable threat intelligence reports from the data.

**Deliverable:** LLM-driven analysis converting raw attacks into understandable, contextualized intelligence.
**Definition of Done:** Given an attack, the system produces a clear summary of what the attacker did, what they were looking for, and which MITRE ATT&CK techniques they utilized.

---

### 🔹 Phase 6 — Threat Intelligence Dashboard (Weeks 7–8)

**Objective:** Present all threat intelligence in a usable format.

**Tasks:**
- [ ] Build the dashboard using Streamlit.
- [ ] Show a **map** of attack origins.
- [ ] Display **patterns** (attack types, most common credentials and commands, timeline trends).
- [ ] Display **MITRE ATT&CK coverage** (observed techniques).
- [ ] Integrate **summaries and reports** generated by the LLM.

**Deliverable:** A dashboard presenting the extracted threat intelligence.
**Definition of Done:** A user can open the dashboard and immediately understand which threats the system has captured and analyzed.

---

### 🔹 Phase 7 — Packaging and Presentation (Weeks 8–10)

**Objective:** Showcase the system's value.

**Tasks:**
- [ ] Containerize the analysis system (reusing your deployment patterns).
- [ ] Write the final README: detailing the problem, safety framework, design decisions, and real findings.
- [ ] Record a video showing the system and, most importantly, **real-world findings** (analyzing real attacks).
- [ ] Write a blog post sharing the project journey and what you discovered about real-world threats.

**Deliverable:** Containerized system + outstanding README + video + blog post, showcasing real-world findings.
**Definition of Done:** An observer can understand the project in two minutes, grasp its sophistication (cybersecurity + AI + real data), and review actual findings.

---

## 6. The Ideal README (Brief Checklist)

The README should include: an engaging title and description; the problem and why it matters; an architecture diagram; a GIF or video of the dashboard showing **real findings** (a major hook); the tech stack with badges; setup instructions; a **design decisions** section (why Cowrie, why a local LLM, why MITRE ATT&CK); a **safety and legal** section (how you isolated the honeypot, precautions taken); and, highly importantly, a **findings** section (what you discovered about real attacks). (This section can be developed in further detail later.)

---

## 7. Common Pitfalls to Avoid

| Pitfall | Why It Is Bad | What to Do |
|-------|-----------------|-----------|
| Poorly isolated honeypot | Could compromise production systems or be used to attack third parties | Strict isolation: dedicated VPS, firewall, no connection to actual systems |
| Attacking back at the attacker | It constitutes unauthorized access: illegal, regardless of intent | Never; only observe and record |
| Analyzing everything manually | Unfeasible given the sheer volume of logs a honeypot generates | That is what AI is for: automate the analysis |
| Using a commercial API for the LLM | Incurs a cost for each analyzed command; data leakage risks | Local LLM with Ollama |
| Sticking to basic statistics | Misses out on the AI aspect, which is the key differentiator | Perform ML and LLM analysis, not just basic counting |
| Failing to map to a standard | Raw intelligence holds less value in isolation | Map to MITRE ATT&CK, the sector's language |
| Ignoring the legal dimension | In security, this is a real risk and a sign of immaturity | Document and respect the legal and ethical framework |

---

## 8. Stretch Goals (Going Further)

- **LLM-Powered Honeypot (Beelzebub):** Replace or supplement Cowrie with a honeypot that uses an LLM to generate dynamic responses, making it much harder for an attacker to detect.
- **AI-Attacker Detection:** A highly relevant topic; detecting, through behavioral patterns, when an attacker is actually an LLM agent rather than a human or a classic script.
- **Real-Time Alerting:** Process attacks as they occur and trigger alerts (e.g., via Slack) for particularly interesting or novel attacks.
- **Multiple Honeypots:** Deploy several types (SSH, HTTP, etc., similar to T-Pot) to capture a broader spectrum of threats.
- **Analysis of Captured Malware:** Securely and in isolation, analyze binaries that attackers attempt to download.
- **Threat Intelligence Feed:** Publish your findings as a reusable feed of IOCs (Indicators of Compromise).

---

## 9. Learning Resources

- **Cowrie Documentation:** The reference for deploying and configuring the honeypot.
- **MITRE ATT&CK:** The adversary technique framework; it is highly recommended to familiarize yourself with its structure (tactics and techniques).
- **Ollama Documentation:** For the local LLM (which you already know from the RAG project).
- **Threat Intelligence and Honeypot Resources:** To understand the context of the field (what threat intelligence is, how honeypots are used in practice, and their limitations).
- **Concepts to Master:** Honeypot types and the interaction-versus-risk trade-off; what threat intelligence is; the MITRE ATT&CK framework; legal and ethical considerations of operating a honeypot; and how unsupervised ML and LLMs contribute to security analysis.

---

## 10. Milestones Tracker

| Week | Milestone | Status |
|--------|------|--------|
| 1 | Environment + foundations + safety framework | ⬜ |
| 1-2 | Honeypot deployed and capturing, isolated | ⬜ |
| 2-3 | Log ingestion and structuring | ⬜ |
| 3-4 | Enrichment with threat intelligence context | ⬜ |
| 4-5 | ML analysis (patterns, classification, anomalies) | ⬜ |
| 5-7 | LLM analysis (summary, intent, MITRE) | ⬜ |
| 7-8 | Threat intelligence dashboard | ⬜ |
| 8-10 | Packaging, README, video, findings | ⬜ |

---

**The ultimate goal:** When someone looks at this project, they should think, *"this person understands security and AI, and has actually worked with real threats."* It is not an exercise using toy datasets, but a system that captures real-world attacks and translates them into intelligence using AI, operated with the responsibility that cybersecurity demands. Combined with your MLOps (production), RAG (applied AI), and XAI (responsible AI) projects, this adds a highly sought-after dimension: **cybersecurity applied with AI** using real data. It is the kind of project that stands out in an interview.

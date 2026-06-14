# AI-Driven Threat Analysis Honeypot — Fundamentals and Design

> This document represents the conceptual work prior to writing code. It covers what a honeypot and threat intelligence actually are; the legal and security dimensions that are unavoidable in this project; exactly what the system does and how; the use case and who it impresses; the technology stack justified piece-by-piece; and the repository architecture. Understanding these foundations is what separates a project that simply "sets up a honeypot and looks at logs" from one that demonstrates that you understand security, AI, and how to operate both responsibly.

> **Security and Legal Note, from the outset:** a honeypot attracts real attackers, so operating it carries risks that must be taken seriously—a theme that runs throughout this entire project. The decoy must be **completely isolated** from any real system; it must not be usable as a stepping stone to attack third parties; and you must **never** counter-attack an attacker, even for "investigation" purposes, because accessing their system would constitute unauthorized access, which is illegal regardless of intent. We only observe and log. Approaching this dimension with rigor is not bureaucracy; it is precisely what demonstrates maturity in a security project, just as the disclaimer did in the medical project.

---

## Introduction: What This Project Actually Is

To understand this project, we must begin with two concepts: the honeypot and threat intelligence.

A **honeypot** is a **decoy**: a system deliberately designed to look attractive or vulnerable to an attacker, but which serves no legitimate purpose other than being attacked. This is where its elegance lies, and it is worth understanding well because it is the key to everything: since no legitimate user should ever interact with this system, **any interaction with it is, by definition, suspicious**. There is no need to separate good traffic from bad, because all traffic is bad. This fundamentally solves the problem that plagues almost all security detection (distinguishing signal from noise): in a honeypot, everything is a signal.

**Threat intelligence** is the knowledge about threats (who is attacking, how, with what tools and techniques, and with what intent) used to build better defenses. And here is the connection: a honeypot is a **first-hand source of threat intelligence**. Instead of reading reports about what happens to others, you observe real attacks against your own decoy, in real-time. This is precisely what security teams do to understand the threat landscape.

### Honeypot Types and the Core Trade-Off

Not all honeypots are created equal, and understanding their types demonstrates sound judgment because it reveals a fundamental trade-off. They are classified by their **level of interaction**. A **low-interaction** honeypot simulates just enough of a service to log connection attempts: it is inexpensive and highly secure, but captures very little data. A **high-interaction** honeypot is a real, complete system that yields the richest data possible, but at the cost of maximum risk (if compromised, a real system is compromised). In the middle lies **medium-interaction**, which simulates a convincing service (for example, a Linux shell with a fake filesystem) and logs everything the attacker does, without being an actual operating system that can be truly compromised.

The trade-off is clear: **higher interaction means richer data, but also greater risk**. This is the core design pivot of any honeypot project, and understanding it allows you to justify your choice. For this project, medium-interaction (using Cowrie) is the sweet spot: it provides data rich enough for interesting analysis (every command typed by the attacker, their credentials, what they attempt to download) with a controllable risk profile.

### The Most Important Idea: Capturing Is Easy, Analysis Is the True Value

There is one core idea that should be internalized from the beginning, as it is the soul of this project—and the equivalent to "the model is the small part" in the MLOps project or "retrieval rules" in the RAG project: **capturing attacks is the trivial part; the true value lies in converting a flood of raw logs into actionable intelligence**. As soon as you expose the decoy to the internet, attacks start arriving on their own in massive volumes: a honeypot can generate tens of thousands of events in just a few days. The bottleneck—and therefore the value—is not in *having* the data, but in *making sense* of it at that scale. Analyzing all of this by hand is impossible.

This is where AI comes in, making it the heart of the project. A honeypot is only as valuable as your capacity to analyze what it captures, and that capacity is precisely what you build: using machine learning to find patterns at scale, and a language model to summarize, interpret, and contextualize the attacks. The project is not just "a honeypot"; it is "an AI-powered threat intelligence system, fueled by a honeypot."

### Who It Impresses and Why

As in your other projects, it helps to be explicit about the target audience. The **security professional** interviewing you will value that you safely operated a honeypot, captured real attacks, and mapped the techniques to MITRE ATT&CK—that is real-world security work, not just theory. The **AI engineer** will see that you applied ML and LLMs to a genuine problem (analyzing security logs at scale) using a local model. The **recruiter** will pick up on three strong signals: the **real-world data** angle, the rare combination of **cybersecurity and AI**, and a dashboard displaying genuine findings. And everyone will appreciate the **maturity** of having carefully managed the legal and security aspects.

With all this in mind, every decision in this document points toward a single conclusion: that anyone who views the project will think, *"this person understands security and AI, and has worked with real-world threats responsibly."*

---

## 1. What You Are Going to Build Exactly

The system goes from the decoy to intelligence across a series of layers built on top of one another:

```
   Internet (real attackers)
        │
        ▼
   [ 1. Honeypot (Cowrie) ]  ──►  the isolated decoy that captures every action
        │  (JSON logs)
        ▼
   [ 2. Ingestion and structuring ]  ──►  sessions, IPs, commands, credentials, payloads
        │
        ▼
   [ 3. Enrichment ]  ──►  geolocation + threat intelligence (known malicious IP?)
        │
        ▼
   [ 4. Analysis ]
        ├── Classical ML  → cluster and classify attacks, detect anomalies (at scale)
        └── Local LLM     → summarize, infer intent, map to MITRE ATT&CK (interpret)
        │
        ▼
   [ 5. Intelligence Dashboard ]  ──►  map, patterns, techniques, reports
```

The **first layer is the honeypot**: the decoy which, isolated and exposed to the internet, captures everything attackers do, logging it in JSON. It is the data source and, as discussed, the part that runs on its own.

The **second layer is ingestion**: converting raw logs into clean, structured data (sessions, source IPs, executed commands, attempted credentials, files the attacker tried to download). This is data engineering work, built with the rigor you already practiced in MLOps.

The **third layer is enrichment**, which begins turning "attack data" into "intelligence" by adding context to each attack. Which country does the IP come from (geolocation)? Is it an IP already known for malicious activity (cross-referencing it with intelligence feeds)? An attack with context is worth far more than a standalone IP.

The **fourth layer, analysis, is the heart of the project**, and consists of two complementary halves. **Classical ML** is responsible for finding patterns *at scale*: clustering similar attack sessions (to discover campaigns or common patterns), classifying attack types, and detecting anomalous sessions that warrant attention. The **local LLM** handles the *interpretive* aspect: taking a session and summarizing it in plain language, inferring what the attacker was looking for, and mapping their actions to MITRE ATT&CK techniques. One provides the quantitative and big-picture view; the other provides the qualitative understanding of each specific case.

And the **fifth layer is the dashboard**: the interface that presents all of this intelligence in a usable format (a map of origins, predominant patterns, technique coverage, generated reports). It is what transforms raw analysis into something that can be viewed and communicated.

---

## 2. The Use Case: From Real Attacks to Threat Intelligence

It is worth pausing to look at what this project solves and why it is so powerful, as it combines several uncommon arguments.

### Real-World Data: The Great Differentiator

This is likely the project's biggest advantage, and it should be leveraged to the fullest. The vast majority of portfolio projects (and many research papers) use public, synthetic, or outdated datasets because **real attack data is scarce and proprietary**: organizations simply do not share it. A honeypot breaks down this barrier because it generates **real, fresh attack data**: actual adversaries from all over the world attacking your decoy right now. Being able to say in an interview, "I analyzed thousands of real attacks that I captured myself, originating from these regions and employing these techniques" has an impact that no downloaded dataset can match. It demonstrates initiative and connects you with the realities of the field rather than an abstraction.

### Cybersecurity and AI: A Sought-After Combination

Cybersecurity is, on its own, a sector of massive and growing demand; the same is true for AI. A project that brings them together in a substantive way (a honeypot whose data you analyze using ML and LLMs) showcases a profile right at a highly sought-after intersection, directly connecting to your interest in security. Few junior candidates can present something like this.

### Tangible Threat Intelligence and a Genuine AI Problem

The output of the project is not abstract: it is **actionable intelligence** (who is attacking, from where, using which techniques, mapped to the standard MITRE ATT&CK language), which is exactly the kind of product real-world security teams generate. And the AI you use is not decorative; it solves a genuine and well-recognized problem: honeypots generate volumes of logs far too massive for manual analysis. Applying ML for patterns and an LLM for interpretation represents a real, modern application of AI to security.

### The Legal and Security Dimension: Maturity, Not Just a Formality

And here is the responsible face of the project, which is both an obligation and an opportunity to demonstrate maturity (the equivalent to the disclaimer in the medical project). Operating a honeypot carries real legal risks and nuances that you must understand and respect.

**Isolation** is the first and most important principle: if the honeypot is poorly configured, an attacker could compromise it and use it as a launching pad to attack *third parties* (which could hold you liable) or to breach your actual infrastructure. That is why the decoy must be completely isolated, with no access to anything real and no ability to initiate outbound attacks. Second, the golden rule: **never counter-attack**. No matter how clearly you see who is attacking you, accessing their system (even to "investigate" or "recover" something) constitutes unauthorized access, which is illegal regardless of your intent. Your role is strictly to observe and log. There are additional nuances as well (such as capturing attacker data, which varies by jurisdiction, or the delicate area of avoiding "entrapment"). Documenting and respecting all of this, rather than ignoring it, is precisely what distinguishes someone who understands the responsibility of operating security tools, and it is a core part of what this project demonstrates.

---

## 3. The Tech Stack, Justified Piece-by-Piece

As in your other projects, choosing your tools wisely and knowing why you chose them demonstrates sound judgment. The **philosophy** organizing this stack is twofold: using standard security tools (the honeypot, the threat framework) and combining them with your AI and data foundations from previous projects—all operated securely and, where appropriate, locally.

### Cowrie: The Honeypot

Cowrie is the community standard for SSH and Telnet honeypots, and is ideal for this project. As discussed, it is **medium-interaction**: rather than a simple decoy that logs connections, it simulates a convincing Linux shell with a fake filesystem, logging every command the intruder types, every credential attempt, and every file they try to download. This provides you with rich and, importantly, JSON-structured data that is easy to process. It is mature, highly tested, and backed by a large community, meaning abundant documentation. Other alternatives worth knowing about (mentioning them shows you understand the landscape): Deutsche Telekom's **T-Pot** is a complete platform combining over twenty honeypots with analytics via the Elastic Stack, but it is much heavier; and **Beelzebub** is a honeypot that uses an LLM to generate dynamic responses, making it harder for attackers to detect—an advanced option that fits well as a future enhancement.

### Isolation: A Dedicated VPS, Docker, and Firewall

Deployment is not a minor detail; it is a fundamental part of the security design. The standard and recommended approach is a **cheap, dedicated VPS** (a virtual cloud server) separated from everything else, with the honeypot **containerized** (Docker) and a **firewall** to guarantee that the decoy cannot access anything real or initiate outbound connections. This configuration materializes the isolation principle we discussed.

### Analysis: scikit-learn and a Local LLM with Ollama

The analysis brings together your two previous projects. For **classical ML**, you use **scikit-learn**, relying primarily on unsupervised techniques: clustering to discover groups of similar attacks, classification of attack types, and anomaly detection for unusual sessions. This reflects the data and modeling rigor you bring from MLOps. For the **interpretive** analysis, you use a **local LLM with Ollama**, reusing everything you learned in the RAG project. There are two compelling reasons for it to be local that are worth explaining: **cost** (analyzing thousands of captured commands with a commercial API would cost money with every call, whereas a local model is free) and its suitability for continuous analysis over large volumes of data. The LLM translates a cryptic attack session into a readable explanation, infers intent, and maps it to the threat technique framework.

### MITRE ATT&CK: The Industry Standard Language

**MITRE ATT&CK** is the standard framework that catalogs attacker tactics and techniques. Mapping your captured attacks to ATT&CK is what elevates your analysis from something "homegrown" into something any security professional instantly recognizes and values. It proves you speak the industry's language and gives your intelligence a standard, comparable format.

### Enrichment and Dashboard

For **enrichment**, you use **GeoIP** (to geolocate origin IPs and track where attacks are coming from) and **threat intelligence** sources like AbuseIPDB (to cross-reference IPs with known malicious address databases). For the **dashboard**, **Streamlit**—which you already master—allows you to build a low-code interface to present all the gathered intelligence: an origin map, patterns, MITRE ATT&CK coverage, and the LLM-generated reports.

### Stack Summary

| Layer | Tool | Purpose / Problem Solved |
|------|-------------|--------------|
| Honeypot | Cowrie | Capture real attacks (SSH/Telnet, medium-interaction) |
| Isolation | VPS + Docker + Firewall | Safely expose the decoy |
| Ingestion | Python + pandas | Structure the JSON logs |
| Enrichment | GeoIP + Threat Intel (AbuseIPDB) | Context: origin and reputation |
| ML | scikit-learn | Patterns, classification, anomalies at scale |
| LLM | Ollama (local) | Summary, intent, mapping to MITRE |
| Framework | MITRE ATT&CK | Standard language for techniques |
| Dashboard | Streamlit | Present the threat intelligence |
| Quality | uv, pytest, ruff, Docker | Reused from your previous projects |

---

## 4. Repository Architecture

As in your other projects, a clean directory structure communicates professionalism and is organized around the system's data flow:

```
honeypot-ai-threat-intel/
├── src/
│   ├── ingestion/parse_logs.py    # parse Cowrie JSON logs
│   ├── enrichment/enrich.py       # geolocation + threat intelligence
│   ├── analysis/
│   │   ├── ml.py                  # clustering, classification, anomalies
│   │   └── llm.py                 # LLM analysis (summary, intent, MITRE)
│   └── config.py                  # centralized configuration
├── dashboard/app.py               # the threat intelligence dashboard
├── honeypot/
│   ├── docker-compose.yml         # isolated Cowrie deployment
│   └── cowrie.cfg                 # honeypot configuration
├── data/                          # captured logs (gitignored)
├── docs/
│   ├── context.md                 # the problem and threat intelligence
│   └── legal_safety.md            # legal, ethical, and safety considerations
├── tests/
├── notebooks/                     # exploration (exploration only)
├── pyproject.toml
├── Makefile
└── README.md
```

The organizing principle of this structure is the **separation of system layers**. The subfolders within `src/` correspond directly to the layers we reviewed: `ingestion` (parsing logs), `enrichment` (adding context), and `analysis` (ML and LLM, separated into distinct modules because they hold different responsibilities). The `dashboard` lives in its own directory, and uniquely to this project, there is a `honeypot/` directory for configuration and isolated deployment of the decoy, kept separate from the analysis code. Two pieces in `docs/` warrant specific mention: `context.md` (which frames the problem and threat intelligence) and, above all, `legal_safety.md`, because in a security project, documenting legal and security considerations is just as important as writing the code—having this in place demonstrates you take this dimension seriously. As in your other projects, you also reuse your foundation of best practices (centralized configuration, testing, Docker, Makefile), which accelerates development and provides coherence to your portfolio.

---

## In Summary

Before writing any code, the essentials are already clear: you are building an **AI-powered threat intelligence system, fueled by a honeypot**. An isolated decoy (Cowrie) captures real attacks from the internet; a pipeline structures them and enriches them with context; an ML-based analysis finds patterns at scale while a local LLM interprets them and maps them to MITRE ATT&CK; and a dashboard presents the resulting intelligence. You have understood the underlying concepts (what a honeypot is, the trade-off between interaction and risk, what threat intelligence entails), the core idea (that capturing data is easy and the true value lies in analysis, which is where AI comes in), and the legal and security dimension that this project demands you treat with seriousness. You have a stack that combines standard security tools with your AI and data foundation, all operated safely and locally. And you have an architecture that mirrors the system's layers while reusing your best practices.

All of this shares a common thread: every decision is designed so that when someone evaluates your work, they conclude that you understand security and AI, that you have worked with real threats, and that you have done so with the responsibility the domain demands. With these foundations clear, you can now begin Phase 0, knowing not only what you are going to do, but why it matters and what level of care it requires.

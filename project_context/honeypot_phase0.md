# Phase 0 — Setup, Fundamentals, and Security

> This phase lays the foundation, and in this project, it has a distinct characteristic that must be kept crystal clear from the very beginning: **security comes before deployment**. In a typical project, setup is just plumbing that is quickly dealt with to get to the interesting parts. Not here: before exposing a decoy to real attackers, you must understand and document how you will isolate it, what you can and cannot legally do, and the golden rule of never counterattacking. Deploying first and thinking about security later would be irresponsible and, potentially, dangerous. That is why this phase is not about "preparing the environment," but rather "preparing the ground responsibly." It is also where you demonstrate from minute one that you understand the security dimension, which is precisely what distinguishes a serious project in this field.

**Phase objective:** environment ready, understanding honeypots and threat intelligence, and establishing a clear legal and security framework.  
**Duration:** first days of week 1.  
**Upon completion, you will have:** a well-structured repository, a solid understanding of the domain (what you will capture and how you will analyze it), and, most importantly, the documented legal and security framework along with an isolated deployment plan—all before exposing anything to the internet.

---

## The Big Picture

This phase is about responsible preparation across four fronts, and note that the actual deployment is not here (it belongs to Phase 1): here, we only prepare and plan.

```
   [ 1. Repository and environment ]  ──►  the engineering foundation (reused)
   [ 2. Understand the domain ]       ──►  honeypots, threat intelligence, MITRE ATT&CK
   [ 3. Legal and security framework] ──►  isolation, never counterattacking, legal nuances
   [ 4. Isolated deployment plan ]    ──►  which VPS, how to isolate it (to execute in Phase 1)
```

---

## Step 1 — The Repository and the Environment

You start, as in your other projects, by setting up the engineering foundation, which you already master and can reuse almost as-is. Create the repository with the structure we saw in the fundamentals, the environment with `uv`, code quality tools with `ruff`, and a `Makefile` with the usual shortcuts.

```bash
uv init honeypot-ai-threat-intel
cd honeypot-ai-threat-intel
uv add pandas                  # to start; the rest will come in their respective phases
uv add --dev pytest ruff
mkdir -p src/{ingestion,enrichment,analysis} dashboard honeypot data docs tests notebooks
```

A note on dependencies: unlike other projects, here the honeypot (Cowrie) **is not a Python dependency**, but rather a service that you will deploy separately (containerized) in Phase 1. Therefore, in this phase, the Python environment is lightweight; you will add the analysis dependencies (scikit-learn, Ollama client, Streamlit, GeoIP) in the phases where they are needed. The `honeypot/` directory will house the decoy's configuration and deployment, separated from the analysis code—a separation reflecting that the decoy and the system analyzing it are two different things (which will live on different machines).

As in your previous projects, configure `.gitignore` to exclude the `data/` folder (captured logs do not go to the repository), and have the `Makefile` ready with `make test`, `make lint`, etc. This reused foundation saves you time and brings consistency to your portfolio.

---

## Step 2 — Understanding the Domain

Before touching anything, spend some time understanding the domain thoroughly. Just as in the medical project, understanding what you are going to handle is not a preliminary formality but a first-rate task: you need to know what you will capture and how you will analyze it. Document this understanding in `docs/context.md`, which will also serve as material for the README.

Make sure you are clear on the concepts we covered in the fundamentals. **What a honeypot is** and, above all, the trade-off between **interaction level and risk** (low interaction: minimal data, low risk; high interaction: rich data, high risk; medium interaction, like Cowrie: the sweet spot for this project). **What threat intelligence is** and why a honeypot is a first-hand source. And the key idea: in a decoy, all traffic is, by definition, suspicious, which greatly simplifies the analysis.

Also, take a first look at **MITRE ATT&CK**, as it is the framework you will map the attacks to, and it is wise to become familiar with its structure early on. ATT&CK organizes attacker behavior into **tactics** (the "what" they are looking for: initial access, execution, persistence, exfiltration...) and **techniques** (the "how" they achieve it). Understanding this schema from the start will help you later on to know what you are looking for when analyzing attacks, and to speak the industry-standard language. You don't need to master it completely right now; understanding its logic is enough.

Understanding the domain beforehand is what will allow you, when attacks start coming in, to recognize what you are seeing instead of staring at a mountain of log lines without knowing how to interpret them.

---

## Step 3 — The Legal and Security Framework

This is the most important step of the phase, and the one that must be completed **before** deploying anything. Operating a honeypot comes with real responsibilities; documenting and respecting them is both an obligation and one of the things that demonstrates the greatest maturity in a security project. Document all of this in `docs/legal_safety.md`. There are several principles you must internalize.

**Isolation** is the first and most important. The honeypot must be completely separated from any system you care about, with no access to your real infrastructure. And, crucially, it must be configured so that it cannot be used as a **stepping stone or launchpad to attack third parties**: if an attacker compromises your decoy and uses it to attack others, you could be held liable. This is the rationale behind the restrictions you will plan in the next step.

The **golden rule: never counterattack**. No matter how much you see who is attacking you and from where, you must never access their system—not to "investigate," not to "recover" anything, and not out of curiosity. Accessing someone else's system without authorization is illegal, regardless of whether that system was attacking you first. Your role is strictly to **observe and log**. This is a line that must not be crossed.

There are also **legal nuances** worth knowing and documenting, although their details vary by jurisdiction (and you should inform yourself about your country's regulations; this is not legal advice, but rather a list of issues to keep in mind). The **data capture** of attackers can have implications under local communications interception laws, so it is wise to limit yourself to logging what happens inside the decoy itself and nothing beyond that. There is also the delicate ground of not actively **inducing** criminal behavior: you present a passive and vulnerable decoy; you do not provoke or solicit specific attacks. And it is worth keeping in mind the nuance that a "harmed" attacker could, ironically, claim to be a victim, which is another reason to limit yourself to observing and never damaging or retaliating.

Lastly, document the **nature of the project**: it is a research and educational honeypot, operated responsibly and in isolation, with the sole purpose of studying threats. Putting this in writing, along with the previous principles, is not a mere formality: it communicates that you understand the responsibility of operating security tools, which is exactly what an industry evaluator looks for.

---

## Step 4 — Planning the Isolated Deployment

With the security framework clear, you plan (but do not yet execute) how to deploy the decoy in an isolated manner. This planning is the technical translation of the principles from the previous step, and it should be decided before starting Phase 1.

The core decision is **where**: the recommended option is a **cheap, dedicated VPS** (a virtual private server in the cloud, from any of the many budget-friendly providers), used exclusively for this purpose and separated from absolutely everything else. The rule is to never run a honeypot on a machine that has access to anything you care about; it must be a disposable and isolated environment.

The **how to isolate it** takes shape in several measures you plan now. The most important one is **restricting outbound traffic** from the honeypot: configuring the firewall so that the decoy can receive connections (which is its purpose) but cannot *initiate* outbound attacks, preventing it from serving as a launchpad against third parties. This outbound restriction is, technically, the most important security measure of all. Additionally: run Cowrie in a container and with a non-privileged user, so that even if something escapes the simulation, it remains contained; move your actual administrative access to a non-standard port and protect it thoroughly (using SSH keys, not passwords), as the standard SSH port will be occupied by the decoy; and plan how you will safely **extract the logs** to analyze them on *another* machine (analysis is not performed on the exposed server; instead, data is moved to a secure environment). Also plan to monitor the health and resource consumption of the honeypot itself.

Having this plan decided and documented means that, when you reach Phase 1, you will deploy securely and with clear criteria, rather than improvising.

---

## Step 5 — Documenting Decisions

As in your other projects, keep a record of key decisions in the documentation: which honeypot you chose (Cowrie) and why, which VPS you will use and how you will isolate it, and a summary of the legal and security framework. Having this in writing will serve as material for the README, help you maintain consistency, and demonstrate that you have made well-thought-out decisions, especially regarding the security aspect.

---

## Verification: The Definition of Done

The phase is complete when the following are met:

- [ ] The repository has the structure, the environment configured with `uv`, code quality tools, and the Makefile.
- [ ] You understand honeypots (types, the interaction/risk trade-off), threat intelligence, and the logic of MITRE ATT&CK, and have documented this in `docs/context.md`.
- [ ] The legal, ethical, and security framework is documented in `docs/legal_safety.md` (isolation, never counterattacking, legal nuances).
- [ ] You have a concrete isolated deployment plan (which VPS, how to restrict traffic, how to extract logs).
- [ ] **The key test:** you understand what you are going to deploy and why, and you are clear on (and have documented) the legal and security precautions.

The key test has two halves reflecting the dual nature of this phase: understanding (knowing what a honeypot is, what you will capture, and how you will analyze it) and responsibility (having clear and documented precautions). The fact that the second half carries as much weight as the first is characteristic of a security project: here, being prepared to operate responsibly is just as important as knowing what you are going to build.

---

## Deliverables and What Comes Next

By closing Phase 0, you have responsibly prepared the ground: the engineering foundation is set up, you have a solid understanding of the domain (honeypots, threat intelligence, MITRE ATT&CK), and, above all, the legal and security framework is documented along with an isolated deployment plan—all before exposing anything. You have started the project exactly where a security professional would: by making sure you understand what you are going to do and that you can do it without risk to yourself or third parties.

The next step, **Phase 1**, executes that plan: **deploying the honeypot securely**. You will launch Cowrie on the isolated VPS, configure it (the fake shell, file system, JSON logging), apply the isolation measures you planned (especially outbound restriction), and expose it to the internet to start capturing real attacks. It is an exciting moment, as you will see the first real attacks hitting your decoy within a few days. You have gone from "understanding what I will deploy and with what precautions" to being on the verge of "having a honeypot capturing real threats, securely."

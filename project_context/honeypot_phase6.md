# Phase 6 — The Threat Intelligence Dashboard

> In this phase, you make all the intelligence you have extracted visible and explorable. After the previous phases, you have acquired significant value (enriched sessions, patterns, LLM analysis, reports), but it lives in data files and text reports that are not very accessible. The dashboard is the face of the project: the place where someone can see, at a glance, what threats the system has captured and understood. And there is an architectural point specific to this project that is worth clarifying from the start, as it distinguishes it from the dashboard you created in the medical project: here, the dashboard **presents already computed intelligence; it does not calculate it live**. The heavy analysis (clustering, and especially the LLM analyzing sessions) was done in batches during the previous phases because it is computationally expensive; the dashboard simply loads these results and visualizes them. It is a fast presentation layer on top of pre-computed intelligence.

**Phase objective:** To present all threat intelligence in a usable format.  
**Duration:** Weeks 7-8.  
**Upon completion, you will have:** An interactive dashboard that presents the extracted threat intelligence (an origin map, patterns, MITRE ATT&CK coverage, and LLM reports) so that anyone can understand at a glance what threats the system has captured and analyzed.

---

## The Big Picture

The dashboard brings together the intelligence from phases 3, 4, and 5 in a visual interface:

```
   ┌────────────────────────────────────────────────────────┐
   │  🛡️ Threat Intelligence (honeypot)                      │
   │  [ Sessions: N ]  [ Unique IPs: M ]  [ Countries: K ]    │
   ├────────────────────────────────────────────────────────┤
   │  🗺️  Origin Map (from enriched coordinates)            │
   │  📊  Patterns (commands, credentials, countries, time) │
   │  🎯  MITRE ATT&CK Coverage (observed techniques)       │
   │  📝  LLM Reports (what each campaign does, intent)     │
   └────────────────────────────────────────────────────────┘
```

You are already familiar with Streamlit from your previous projects (`uv add streamlit` if you are starting from scratch).

---

## Step 1 — Architecture: Presenting, Not Calculating

Before diving into the code, it is worth establishing this design decision, as it demonstrates sound judgment and provides an instructive contrast to your previous project. In the medical dashboard, you calculated the SHAP explanation **live** for each patient the user entered, which made sense because that calculation is instantaneous. Here, the situation is the opposite: the analysis (clustering, and especially the LLM analyzing sessions) is **expensive and done in batches**, offline, during the previous phases. This is why the dashboard does not recalculate anything: it simply **loads the already calculated results** (enriched sessions, cluster analyses, reports) and presents them.

This separation between heavy batch analysis and a lightweight presentation layer is the correct architecture when analysis is computationally expensive. Knowing when to apply it (as opposed to the live calculation of the medical project) is precisely the kind of design judgment that distinguishes a good engineer. In Streamlit, you load the artifacts only once using `@st.cache_data`. Create `dashboard/app.py`:

```python
import json

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Threat Intelligence (honeypot)", page_icon="🛡️", layout="wide"
)


@st.cache_data
def load_data():
    sessions = pd.read_parquet("data/sessions_enriched.parquet")
    with open("data/cluster_analyses.json", encoding="utf-8") as f:
        analyses = json.load(f)
    return sessions, analyses


sessions, analyses = load_data()

st.title("🛡️ Threat Intelligence — Honeypot")
c1, c2, c3 = st.columns(3)
c1.metric("Attack Sessions", len(sessions))
c2.metric("Unique IPs", sessions["src_ip"].nunique())
c3.metric("Origin Countries", sessions["country"].nunique())
```

Right off the bat, the header metrics provide the scale of what was captured: how many attacks, from how many unique IPs, and from how many countries. They immediately communicate something powerful: these numbers are derived from **real attacks**.

---

## Step 2 — The Origin Map

The first panel, and one of the most visually striking, is a map showing where the attacks originate. This is where your investment in enrichment during Phase 3 visually pays off: because you geolocated the IPs and saved their coordinates back then, you can now plot them on a map with a single line of code, as `st.map` directly accepts a DataFrame containing latitude and longitude columns:

```python
st.header("🗺️ Attack Origins")
coords = sessions[["latitude", "longitude"]].dropna()
st.map(coords)
st.caption(f"{len(coords)} geolocated attacks.")
```

Seeing a world map dotted with points, each representing a real attack against your decoy, is one of the most impactful elements of a demonstration because it makes the reality of the threats tangible. At a glance, you can see where you are being attacked from the most, which often reveals interesting geographical patterns. It is a perfect example of how the work from previous phases (geolocating) yields highly visible results here.

---

## Step 3 — Patterns

The second panel displays the attack patterns using the statistics you have already calculated. Streamlit makes it very easy to turn counts into a chart. Show the most frequently executed commands, origin countries, the most tested credentials, and temporal trends:

```python
st.header("📊 Attack Patterns")

col1, col2 = st.columns(2)
with col1:
    st.subheader("Most Executed Commands")
    top_cmds = sessions["commands"].explode().dropna().value_counts().head(15)
    st.bar_chart(top_cmds)
with col2:
    st.subheader("Origin Countries")
    st.bar_chart(sessions["country"].value_counts().head(10))

st.subheader("Attacks Over Time")
por_dia = sessions.set_index("timestamp").resample("D").size()
st.line_chart(por_dia)
```

These panels tell the story of what is happening: what the attackers are trying to do (the commands), where they are coming from, and how activity evolves over time (which sometimes reveals peaks associated with specific campaigns). This is actionable intelligence presented immediately. You can also add the most frequently tested credentials, which are often eye-opening (bots consistently try the same weak combinations, which is a security lesson in itself).

---

## Step 4 — MITRE ATT&CK Coverage

The third panel is one of the most professional components, showcasing the mapping performed by the LLM in Phase 5: displaying which **MITRE ATT&CK** techniques your honeypot has observed. Extract the techniques from the LLM analyses and present them:

```python
st.header("🎯 Observed Techniques (MITRE ATT&CK)")

techniques = []
for analysis in analyses.values():
    for t in analysis.get("mitre", []):
        techniques.append(f"{t.get('id', '?')} — {t.get('nombre', '')}")

if techniques:
    counts = pd.Series(techniques).value_counts()
    st.bar_chart(counts)
    st.caption("MITRE ATT&CK techniques identified in the analyzed attacks.")
```

This panel is especially valuable because it speaks the **industry-standard language**: any security professional viewing your dashboard will instantly recognize a MITRE ATT&CK coverage view and understand which tactics and techniques are in play without further explanation. Presenting intelligence within this framework demonstrates that you understand how real-world security operations work, elevating your dashboard from "some nice-looking charts" to "a threat intelligence tool using the correct industry vocabulary."

---

## Step 5 — LLM Reports

The final panel is what makes all the intelligence understandable to anyone: the **summaries and reports** generated by the LLM in Phase 5. While the charts show the quantitative "what", these reports explain the "what it means" in plain language. Present them in an explorable format, for example using expandable sections, one for each attack pattern:

```python
st.header("📝 Analyzed Attack Patterns")

for cluster, analysis in analyses.items():
    if cluster == "-1":  # anomalies, if you handle them separately
        continue
    title = f"{analysis.get('intencion', 'Attack Pattern')}"
    with st.expander(title):
        st.write(f"**What it does:** {analysis.get('resumen', '—')}")
        st.write(f"**Intent:** {analysis.get('intencion', '—')}")
        techniques = ", ".join(t.get("id", "") for t in analysis.get("mitre", []))
        st.write(f"**MITRE Techniques:** {techniques or '—'}")
```

This is where the entire project pipeline culminates: visitors to the dashboard do not just see how many attacks occurred and from where, but they can read, in plain language, what each attack campaign did and what it was looking for, thanks to the LLM's analysis. This transforms the dashboard from a mere collection of charts into an **intelligence narrative**: it tells the story of the threats, rather than just counting them. It is the accessible culmination of the project's most distinctive phase.

---

## Step 6 — Testing the Dashboard

Launch the dashboard (`uv run streamlit run dashboard/app.py`) and navigate through it as a first-time user would. Verify that the header metrics establish the scale, the map displays the origins of actual attacks, the pattern panels explain what the attackers are attempting and from where, the MITRE ATT&CK coverage presents the techniques in industry-standard language, and the LLM reports explain in plain language what each campaign does.

The question that should guide your testing, which serves as this phase's core criterion, is straightforward: **Does someone opening this dashboard understand, at a glance, what threats the system has captured and analyzed?** If the answer is yes, you have met the objective. Moreover, given that everything shown is based on real data, this dashboard is the ideal centerpiece for your Phase 7 video and README: few things are as impressive as an intelligence panel displaying real-world attacks.

---

## Verification: The "Definition of Done"

The phase is complete when the following criteria are met:

- [ ] The dashboard loads pre-computed intelligence (it does not recalculate it) and presents it.
- [ ] It displays a map of the attack origins.
- [ ] It displays patterns (commands, credentials, countries, temporal trends).
- [ ] It displays MITRE ATT&CK coverage.
- [ ] It integrates the summaries and reports generated by the LLM.
- [ ] **The key test:** Anyone can open the dashboard and understand, at a glance, what threats the system has captured and analyzed.

The key test is immediate understanding: if someone opens your dashboard and grasps—without any explanation—what threats exist, where they come from, what they do, and which techniques they employ, you have successfully made your threat intelligence accessible. That is the ultimate goal of a threat intelligence dashboard: not to lock knowledge away in files, but to put it directly in front of those who need it.

---

## Deliverables and Next Steps

By the end of Phase 6, you will have the project in its final, presentable form: a threat intelligence dashboard that visually and comprehensively unites everything the system has captured and analyzed. You have implemented the correct architecture (a lightweight presentation layer over batch-computed intelligence), realized the visible benefits of your previous work (the geolocated map, the MITRE ATT&CK mapping, and the LLM analytical reports), and created the piece that gives the project its real-world impact by displaying actual threats.

The next and final step, **Phase 7**, focuses on showcasing the full value of the project: **packaging and presentation**. You will containerize the analytical system, write the final README (detailing the security framework, design choices, and particularly a section on actual findings), record a video demonstrating the dashboard and your real-world threat discoveries, and write a blog post. All the work from the seven phases now needs a showcase, and you have exceptional material: real-world data, analyzed using AI, and presented on an interactive dashboard. You have transitioned from "having threat intelligence presented on a dashboard" to "being ready to present a complete project that demonstrates your expertise in both security and AI applied to real-world threats."

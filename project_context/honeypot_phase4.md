# Phase 4 — Analysis with Classical ML

> In this phase, you apply the first layer of automated intelligence to your data. You have thousands of structured and enriched attack sessions, and there are too many to read one by one. This is where machine learning delivers what a human cannot: **finding patterns at scale**. The organizing concept of this phase is a highly useful division between two complementary questions. On one hand, "what are the dominant patterns?": honeypot traffic is dominated by automated and repetitive attacks (bots executing the same scripts over and over), and *clustering* reveals those broad patterns—the campaigns. On the other hand, "what deviates from the norm?": amidst all that automated noise, *anomaly detection* highlights rare and unusual sessions, which tend to be the most interesting ones (a manual attacker, a novel technique). Cluster to find the commonalities, detect anomalies to spot the exceptional.

**Phase objective:** Find patterns in attacks at scale.  
**Duration:** Weeks 4–5.  
**By the end, you will have:** An ML analysis that reveals the patterns of your attacks: key statistics, clusters (campaigns) of similar attacks, a characterization of the attack types, and the anomalous sessions that merit special attention.

---

## The Overall Concept

The workflow for this phase applies several ML techniques to the enriched sessions:

```
   Enriched sessions (Phase 3)
        │
        ├──► [ 1. Statistics ]  ──►  most tested, most common (immediate value)
        │
        ▼
   [ 2. Featurization ]  ──►  convert each session into a numerical vector
        │                      (including TF-IDF of commands: what the attacker did)
        ├──► [ 3. Clustering ]  ──►  group similar attacks (discover campaigns)
        ├──► [ 4. Characterize types ]  ──►  what type of attack each group is
        └──► [ 5. Anomalies ]   ──►  rare sessions that stand out from the noise
```

You already know scikit-learn from your previous projects; you don't need any new dependencies beyond the ones you already have.

---

## Step 1 — Start with Statistics

Before breaking out machine learning, it is worth remembering a maturity lesson you have already applied in other projects: **do not use ML when a simple count answers the question**. Many of the most valuable questions about your attacks can be answered using simple aggregations, which also yield immediate and highly presentable results. Start there. Complete `src/analysis/ml.py`:

```python
import pandas as pd


def attack_statistics(sessions: pd.DataFrame) -> dict:
    """Key attack statistics, without ML."""
    # Most executed commands (flattening the list column)
    commands = sessions["commands"].explode().dropna()
    # Most frequent origin countries (from enrichment)
    return {
        "top_commands": commands.value_counts().head(20),
        "top_countries": sessions["country"].value_counts().head(10),
        "protocols": sessions["protocol"].value_counts(),
        "most_active_ips": sessions["src_ip"].value_counts().head(10),
        "successful_login_rate": sessions["login_success"].mean(),
    }
```

From this, you already get quantifiable and valuable findings: which credentials they test the most (the user/password combinations that bots repeat endlessly), which commands they run the most (revealing what they are trying to do), which countries most attacks originate from, which IPs are the most persistent, and temporal trends (attacks per hour or day). These statistics are fully-fledged threat intelligence, easy to obtain, and excellent material for the dashboard and README. Extract them first, before making things more complex.

---

## Step 2 — Convert Sessions into Features

To apply ML, you need to convert each session (which is a heterogeneous object: an IP, some commands, some counts) into a **numerical vector**. This is the key methodological step of this phase, and the most important decision is which signals to capture. You will combine two types. On one hand, **numerical behavioral signals**: how many login attempts were made, how many commands were run, whether they succeeded in logging in, how long it lasted, and the abuse score. On the other hand—and this is the interesting part—**command signals**: what the attacker *did*, which is the most revealing fingerprint of their behavior. Since commands are text, you vectorize them using TF-IDF, a technique that captures which commands characterize each session.

```python
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler


def featurize(sessions: pd.DataFrame) -> np.ndarray:
    """Converts sessions into numerical vectors for ML."""
    # 1. Behavioral signals (numerical, scaled)
    num = sessions[["n_login_attempts", "n_commands", "n_downloads", "duration"]].fillna(0)
    num = num.assign(
        login_success=sessions["login_success"].astype(int),
        abuse_score=sessions["abuse_score"].fillna(0),
    )
    num_scaled = StandardScaler().fit_transform(num)

    # 2. Command signals (what the attacker did), via TF-IDF
    command_text = sessions["commands"].apply(
        lambda cmds: " ".join(cmds) if isinstance(cmds, list) and cmds else ""
    )
    cmd_features = TfidfVectorizer(max_features=100).fit_transform(command_text).toarray()

    return np.hstack([num_scaled, cmd_features])
```

The reason for including commands via TF-IDF is that they represent the **behavioral footprint** of the attack: two sessions executing the same sequence of commands are, almost certainly, the same type of attack (often the exact same bot), even if they originate from different IPs. Capturing this is what will allow clustering to recognize campaigns. We scale numerical features (using `StandardScaler`) because, as you already know from MLOps, distance-based techniques require variables to be on comparable scales.

---

## Step 3 — Group Similar Attacks

With the sessions vectorized, clustering groups similar ones to **discover campaigns and dominant patterns**. We will use DBSCAN, which offers two advantages for this use case: you do not need to specify the number of clusters beforehand (unlike KMeans), and it labels sessions that do not fit into any dense group as "noise," which aligns perfectly with the nature of our data (many repetitive attacks forming dense clusters, along with a few isolated ones).

```python
from sklearn.cluster import DBSCAN


def cluster_attacks(features: np.ndarray, eps: float = 1.5, min_samples: int = 5) -> np.ndarray:
    """Groups similar sessions. The label -1 flags those that do not fit (noise)."""
    return DBSCAN(eps=eps, min_samples=min_samples).fit_predict(features)
```

Each cluster found represents an attack pattern: for instance, a large group of sessions that only test credentials (a brute-force bot), another group of sessions executing the same sequence to install a cryptocurrency miner, and another recruiting for a botnet. Seeing thousands of sessions condensed into a handful of patterns is precisely the value of this phase: ML reveals the structure hidden beneath the volume. A practical note on judgment: DBSCAN parameters (`eps`, `min_samples`) require tuning based on your data, and with high-dimensional command features, it is worth experimenting; if DBSCAN does not group well, KMeans is a reasonable alternative (by choosing a set number of clusters). What matters is the outcome: coherent groups of similar attacks.

---

## Step 4 — Characterize Attack Types

The task of "classifying attack types" has a nuance that is best approached with honesty, as it demonstrates sound judgment. You do not have true **labels** (no one has told you "this session is brute force, this other is a miner"), so this is not a traditional supervised classification task. What you do instead is **characterize the groups** discovered by clustering: for each group, you look at which commands are typical, how many sessions it contains, what its login rate is, and from there, you label the type of attack it represents.

```python
def characterize_clusters(sessions: pd.DataFrame, labels: np.ndarray) -> pd.DataFrame:
    """Summarizes each cluster to help identify what type of attack it represents."""
    df = sessions.assign(cluster=labels)
    summary = []
    for cluster, group in df.groupby("cluster"):
        commands = group["commands"].explode().dropna().value_counts().head(5)
        summary.append({
            "cluster": cluster,
            "n_sessions": len(group),
            "successful_login_rate": group["login_success"].mean(),
            "avg_commands": group["n_commands"].mean(),
            "typical_commands": list(commands.index),
        })
    return pd.DataFrame(summary)
```

As a complement, you can apply **interpretable heuristic rules** to label types, which are often very clear-cut: a session with many login attempts and zero commands is pure brute force; one that downloads and executes a binary is malware deployment; one that only connects and leaves is a scan. Combining cluster characterization with these rules provides a taxonomy of the attack types you observe. Being transparent about the fact that this is an unsupervised analysis (rather than classification with ground-truth labels) and explaining why demonstrates that you understand the distinction and are not trying to package unsupervised work as supervised.

---

## Step 5 — Detect Anomalies

The final technique answers the other question of this phase: within the ocean of automated and repetitive attacks, which ones **deviate from the norm**? These rare sessions are often the most interesting: a human attacker carefully exploring, a technique you have not seen before, or (as we will see in the stretch goals) even an attacker that is actually an AI agent. To find them, `IsolationForest` is ideal: it isolates observations that differ from the bulk of the data.

```python
from sklearn.ensemble import IsolationForest


def detect_anomalies(features: np.ndarray, contamination: float = 0.02) -> np.ndarray:
    """Flags anomalous sessions. The label -1 indicates an anomaly."""
    model = IsolationForest(contamination=contamination, random_state=42)
    return model.fit_predict(features)
```

The `contamination` parameter indicates the fraction of sessions you expect to be anomalous (for example, 2%). The model flags the ones that stand out from the general pattern with a -1. The underlying idea is powerful: since the vast majority of attacks are automated and similar to one another, *normal* behavior in your honeypot consists of automated attacks, and *anomalous* behavior is precisely what breaks that monotony—which typically deserves human review. Anomaly detection is, therefore, a filter that highlights the few sessions that actually warrant in-depth investigation out of the thousands available. This connects seamlessly to the next phase: these interesting sessions are ideal candidates for in-depth analysis by an LLM.

---

## Step 6 — Testing

Verify that the analysis pipeline works on a few sample sessions. The most useful things to test are that featurization produces the correct shape and that the techniques run and return labels successfully. Complete `tests/test_analysis.py`:

```python
import numpy as np
import pandas as pd

from src.analysis.ml import cluster_attacks, detect_anomalies, featurize


def _sample_sessions(n=30) -> pd.DataFrame:
    return pd.DataFrame({
        "n_login_attempts": np.random.randint(1, 50, n),
        "n_commands": np.random.randint(0, 10, n),
        "n_downloads": np.random.randint(0, 3, n),
        "duration": np.random.rand(n) * 100,
        "login_success": np.random.randint(0, 2, n).astype(bool),
        "abuse_score": np.random.randint(0, 100, n),
        "commands": [["ls", "wget http://x"] for _ in range(n)],
    })


def test_featurize_produces_matrix():
    sessions = _sample_sessions()
    X = featurize(sessions)
    # One row per session
    assert X.shape[0] == len(sessions)


def test_anomalies_returns_labels():
    X = featurize(_sample_sessions())
    labels = detect_anomalies(X, contamination=0.1)
    # One label per session, and all are either -1 (anomaly) or 1 (normal)
    assert len(labels) == X.shape[0]
    assert set(labels).issubset({-1, 1})
```

These tests verify that featurization generates a matrix with one row per session and that anomaly detection produces valid labels. They confirm that the analytical machinery works end-to-end on data with the expected shape. Run them with `make test`.

---

## Verification: Definition of Done

The phase is complete when the following are met:

- [ ] You have extracted key statistics (most common credentials and commands, countries, most active IPs).
- [ ] Sessions are converted into numerical features, including the command footprint (TF-IDF).
- [ ] Clustering groups similar attacks, revealing dominant campaigns or patterns.
- [ ] You have characterized attack types (based on clusters and rules), with transparency regarding their unsupervised nature.
- [ ] Anomaly detection flags unusual sessions that warrant attention.
- [ ] **The key proof:** You can show the predominant attack clusters, attack types, and anomalies using real data.

The key proof is about revealing patterns: if, starting with thousands of real attacks, you can demonstrate what the dominant patterns are, what attack types they represent, and which sessions deviate from the norm, you have succeeded in making ML do what a human could not—bring structure and meaning to volume. You have gone from "I have thousands of sessions" to "I understand what those thousands of sessions actually represent."

---

## Deliverables and Next Steps

Upon wrapping up Phase 4, you have established the first layer of automated intelligence: key statistics, clusters of similar attacks (campaigns), a characterization of the attack types, and anomalous sessions. You have applied the ML rigor of MLOps to a new domain, achieving the useful division of this phase: clustering shows you what is common at scale, and anomaly detection highlights what is exceptional. ML has provided the **structure** that was hidden within the volume.

The next step, **Phase 5**, adds the most sophisticated intelligence layer and the defining hallmark of the project: **analysis using a local LLM**. While ML gives you structural breadth (patterns, clusters), the LLM will give you deep comprehension. It will take the sessions—both representative ones from each cluster and especially the anomalous ones you just detected—and interpret them in plain language, inferring what the attacker was seeking and mapping their actions to MITRE ATT&CK techniques. ML provides breadth; the LLM provides depth. You have progressed from "I see the attack patterns" to being on the verge of "I understand and can explain what each attack was trying to achieve."

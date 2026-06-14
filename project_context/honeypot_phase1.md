# Phase 1 — Securely Deploying the Honeypot

> In this phase, you execute the plan you prepared in Phase 0 and bring the decoy online. It is the most exciting moment of the project: as soon as you expose the honeypot to the internet, real attacks will start arriving, sometimes in a matter of minutes. But "exciting" does not mean "rushed": every step of the deployment has a security implication that must be executed carefully, because you are about to invite real attackers into a system of your own. The good news is that you already did the hard work of thinking about security in Phase 0; here, you just have to apply it rigorously. And remember the foundational concept that now becomes tangible: since no legitimate user will ever touch this system, **everything you capture will, by definition, be a real attack**.

**Phase Objective:** To have a honeypot capturing real attacks in an isolated manner.  
**Duration:** Weeks 1-2.  
**Upon completion, you will have:** Cowrie running on an isolated VPS, convincingly configured, logging attacks in JSON, properly isolated (with no access to real systems and unable to serve as a stepping stone), and capturing real attacks that you can begin to analyze.

---

## The Big Picture

The deployment has an order that matters, because security is interwoven into every step:

```
   [ 1. Prepare the VPS ]  ──►  move your real SSH (first of all!) so you don't get locked out
        │
        ▼
   [ 2. Deploy Cowrie ]  ──►  Docker container, listening, logging to JSON
        │
        ▼
   [ 3. Isolate ]  ──►  firewall: allow inbound to the decoy, RESTRICT outbound
        │
        ▼
   [ 4. Make it convincing ]  ──►  banner, hostname, credentials, file system
        │
        ▼
   [ 5. Expose, verify, & capture ]  ──►  verify everything and watch the attacks roll in
```

---

## Step 1 — Prepare the VPS and Protect Your Access

First and foremost, and where most people go wrong, is **protecting your own access before touching anything else**. The decoy will occupy port 22 (the SSH port), which is where most attacks arrive, so you have to **move your real management access to another port first**. If you skip this, as soon as the decoy occupies port 22, you could find yourself locked out of your own server.

```bash
# On the VPS, edit the SSH configuration
sudo nano /etc/ssh/sshd_config
#   change: Port 22  ->  Port 22022   (any high-numbered port)
sudo systemctl restart ssh
```

And here is the tip that avoids the classic mistake: **before proceeding, open a new connection on the new port and verify that it works**, without closing your current session. If something went wrong, you still have the old session open to fix it.

```bash
# From your machine, in a NEW terminal (without closing the current one):
ssh -p 22022 user@<vps-ip>
```

Only after you confirm that you can log in through the new port, continue. This careful approach is a concrete example of how the order of operations matters in security.

---

## Step 2 — Deploy Cowrie with Docker

With your access secured, you can deploy Cowrie. You will use the official image (`cowrie/cowrie:latest`) with Docker Compose, which is simple and reproducible. Create `honeypot/docker-compose.yml`:

```yaml
services:
  cowrie:
    image: cowrie/cowrie:latest
    restart: always
    ports:
      - "22:2222"    # the decoy's SSH, exposed on the real port 22
      - "23:2223"    # the decoy's Telnet (optional)
    volumes:
      - cowrie-logs:/cowrie/cowrie-git/var   # persist the logs (including cowrie.json)
    environment:
      - COWRIE_TELNET_ENABLED=yes

volumes:
  cowrie-logs:
```

Here is a detail that shows you understand what you are doing, and it has important consequences for the quality of your data. By default, Cowrie listens on ports **2222** (SSH) and **2223** (Telnet), not 22 and 23, to avoid clashing with real services. To ensure it receives the majority of attacks, you need it to be on port 22. There are two ways to achieve this: redirecting the port with `iptables`, or mapping the port directly in Docker (`"22:2222"`). **The correct way here is Docker port mapping**, and the reason is subtle but crucial: if you redirect using iptables over a Docker container, the logs will show the internal Docker IP (something like 172.17.0.1) as the source, rather than the attacker's real IP. Since you will be geolocating and analyzing those IPs in the upcoming phases, losing the real IP would ruin your analysis. Docker's port mapping preserves the attacker's real IP, which is exactly what you need.

Also, note the **volume**: it persists Cowrie's data directory (where `cowrie.json`, the structured log you will analyze, lives) so that the logs survive container restarts. Start up the decoy:

```bash
cd honeypot
docker compose up -d
```

---

## Step 3 — Ensure Isolation

This is the step where you apply the most important security measure you planned, and it should be executed carefully. There are two directions of traffic, and they are treated differently.

**Inbound** is easy: you want the decoy to receive connections (that is its purpose), so you allow inbound traffic to the honeypot ports (22 and 23) and, of course, to your management port (22022). Using the server's own firewall:

```bash
sudo ufw allow 22022/tcp   # your management access (the one you protected!)
sudo ufw allow 22/tcp      # the decoy: SSH
sudo ufw allow 23/tcp      # the decoy: Telnet
sudo ufw enable
```

**Outbound** is the critical part for security, and the reason is what we saw in Phase 0: you must prevent the decoy from being able to **initiate outbound connections**, so an attacker cannot use it as a launching pad to attack third parties (which could make you liable). And here is an important technical nuance that shows expertise: **Docker manages its own iptables rules**, so a simple `ufw default deny outgoing` on the host may not apply to traffic leaving the containers. To truly restrict outbound traffic from a container, the rules must be placed in the `DOCKER-USER` chain of iptables, or, much more cleanly and robustly, by using the **VPS provider's firewall** (the "security groups" or network firewalls that almost all providers offer), which operates outside the machine and is therefore out of reach of Docker's rules. The practical recommendation is precisely that: configure the outbound restriction in your provider's network firewall, allowing only the bare essentials (DNS, and little else), so that the decoy cannot attack anyone no matter how hard an attacker tries.

This outbound restriction has a consequence that is worth knowing and accepting: Cowrie, which is a medium-interaction honeypot, logs malware download *attempts* (the URLs the attacker tries to use), but since it has no outbound access, it will not actually download the real binaries. This is entirely correct and much more secure; analyzing captured malware, if you wanted to, would be a future improvement to be done in an even more isolated environment.

---

## Step 4 — Make the Decoy Convincing

The more convincing the honeypot is, the further attackers will go in their interaction, and the richer the information you capture will be. Cowrie allows you to customize various aspects of its simulation through its configuration (`cowrie.cfg`) and its data files. It is worth adjusting a few things: the **banner** and the **hostname** the attacker sees (to make it look like a real, appealing server rather than a default Cowrie installation), the **accepted credentials** (the `userdb` file, which defines which usernames and passwords let them "in"—allowing some common ones lets you observe what the attacker does *after* gaining access, which is the most interesting part), and the **fake filesystem** that the attacker explores.

A word of balance, though: don't invest too much in this. Cowrie's default options are already reasonably convincing and capture a great deal of activity, so a few simple tweaks (a believable banner and hostname, some accepted credentials) are enough to get started. You can refine how convincing it is later if you find that attackers are detecting the decoy too quickly. Just remember, of course, to never reuse credentials or configurations from your actual systems.

---

## Step 5 — Expose, Verify, and Start Capturing

With everything up and running, you verify that it works and start capturing. First, check that the decoy is listening on the correct ports:

```bash
docker ps
ss -ltnp | grep -E ':22|:23'
```

Next, and this is important, **test it from another machine** (not from the server itself, as local connections behave differently). Try connecting to the decoy and performing a fake login, and observe how it gets logged:

```bash
# From ANOTHER machine (your laptop, for example):
ssh -p 22 root@<vps-ip>
#   try any username/password: you are "attacking" your own decoy to test it
```

And watch the events arriving in the JSON log, which is what you will analyze in the upcoming phases. With the Docker volume, the file is on the host in a path like this:

```bash
sudo tail -f /var/lib/docker/volumes/honeypot_cowrie-logs/_data/log/cowrie/cowrie.json
```

You will see your own login attempt recorded in JSON, with all the details. And then comes the exciting part: leave the decoy exposed, and in a short time (often minutes or hours) **real attacks** will start appearing in that same log, from IPs all over the world, testing credentials, executing commands, and attempting to download files. Every single one of those lines is a real attack that you have captured yourself. Finally, take a moment to **verify isolation**: confirm that from the decoy you cannot reach any of your systems, and that it cannot initiate outbound connections (you can try a ping or an outbound connection from within the container and verify that it fails). This verification is what gives you the peace of mind to operate responsibly.

---

## Verification: The "Definition of Done"

The phase is complete when the following are met:

- [ ] Your real management access is on a port other than 22 and you have verified it.
- [ ] Cowrie is deployed (Docker) and listening, using port mapping that preserves the attacker's real IP.
- [ ] Isolation is applied: inbound permitted to the decoy, **outbound restricted** (in the provider's firewall or the DOCKER-USER chain), with no access to real systems.
- [ ] The decoy is configured in a reasonably convincing manner.
- [ ] Attacks are logged in `cowrie.json`, and you have verified capture by testing from another machine.
- [ ] **The key test:** the honeypot is online, logs attacks in JSON, and you have verified that it is properly isolated.

The key test once again has both sides of the project: that the decoy *works and captures* (attacks appear in JSON) and that it is *properly isolated* (verified, not assumed). In security, "working" without "being secure" is not a finished job; both conditions must be met. If you have a honeypot capturing real attacks and you have confirmed that it cannot do any harm, you have achieved the goal of this phase, and you now have something that very few projects can show: real attack data, captured by you, in a responsible manner.

---

## Deliverables and What's Next

As you close Phase 1, you have the heart of the project beating: a functioning, isolated honeypot capturing real attacks that accumulate in `cowrie.json`. You have rigorously executed the security plan from Phase 0 (protecting your access, preserving the real IP of the attackers, restricting outbound traffic), and you have begun gathering the project's most valuable asset: real threat data. With every hour the decoy remains online, your dataset grows.

The next step, **Phase 2**, begins to make sense of all that: **log ingestion and structuring**. These JSON logs are rich but raw and voluminous; you will write the code to read them and convert them into clean, structured data (sessions, IPs, commands, credentials, payloads), with the same data rigor you already practiced in MLOps. It is the first step in moving from "I have a bunch of attack logs" to "I have attack data that I can analyze." In the meantime, leave the honeypot capturing: the longer you leave it, the richer the intelligence you will extract later. You have gone from "I have a decoy capturing real threats" to being on the verge of "I have those threats in a form ready to analyze."

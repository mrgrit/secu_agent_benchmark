#!/usr/bin/env python3
"""6v6 LIVE capability prober  →  capability_inventory.json

The infra-fit selector keeps a benchmark task ONLY if its required capabilities are present in
this file. Every entry carries probe EVIDENCE (the command run + what was observed), so an
exclusion is *falsifiable*: a task is dropped because a capability is provably absent on the live
range — never because someone "felt" it didn't fit. No LLM. Pure deterministic SSH + docker-exec
enumeration of the running 6v6 containers.

    python3 harness/probe_infra.py            # probe 6v6@0.103, write capability_inventory.json
    python3 harness/probe_infra.py --print     # also dump a human summary
"""
import json, shlex, subprocess, sys, datetime
from pathlib import Path

SSH = ("sshpass -p 1 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
       "-o LogLevel=ERROR -o ConnectTimeout=10 ccc@192.168.0.103")   # aidoyak temp 6v6
OUT = Path(__file__).parent / "capability_inventory.json"

# binaries whose presence/absence gates a whole class of tasks
TOOLS = [
    "nmap", "masscan", "sqlmap", "nikto", "gobuster", "ffuf", "wfuzz", "dirb", "whatweb",
    "wpscan", "nuclei", "msfconsole", "searchsploit", "hydra", "john", "hashcat", "medusa",
    "crackmapexec", "tcpdump", "tshark", "tcpdump", "nc", "ncat", "socat", "curl", "wget",
    "volatility", "vol.py", "vol", "winpmem", "avml", "insmod",            # memory forensics
    "binwalk", "foremost", "fls", "strings", "file",                       # disk/file forensics
    "radare2", "r2", "gdb", "objdump", "readelf", "ghidra",                # reversing
    "openssl", "dig", "nslookup", "dnsrecon",
    "smbclient", "enum4linux", "ldapsearch", "kerbrute", "responder",      # smb / AD
    "aircrack-ng", "frida", "adb", "apktool",                              # wireless / mobile
    "aws", "gcloud", "az", "kubectl", "helm", "terraform",                 # cloud / k8s
    "suricata", "jq", "python3",
]
PROBE_CONTAINERS = ["6v6-attacker", "6v6-siem", "6v6-ips", "6v6-web", "6v6-bastion", "6v6-fw"]

# derived capability classes: name -> tools that satisfy it (ANY present => class present)
CAP_CLASSES = {
    "cap:network-recon":    ["nmap", "masscan"],
    "cap:web-scan":         ["sqlmap", "nikto", "gobuster", "ffuf", "wfuzz", "dirb", "nuclei", "whatweb"],
    "cap:password-attack":  ["hydra", "john", "hashcat", "medusa", "crackmapexec"],
    "cap:exploit-fw":       ["msfconsole", "searchsploit"],
    "cap:pcap-analysis":    ["tshark", "tcpdump"],
    "cap:memory-forensics": ["volatility", "vol.py", "vol", "winpmem", "avml"],
    "cap:disk-forensics":   ["binwalk", "foremost", "fls"],
    "cap:reversing":        ["radare2", "r2", "gdb", "objdump", "ghidra"],
    "cap:crypto":           ["openssl"],
    "cap:smb-ad":           ["smbclient", "enum4linux", "ldapsearch", "kerbrute", "responder", "crackmapexec"],
    "cap:wireless":         ["aircrack-ng"],
    "cap:mobile":           ["frida", "adb", "apktool"],
    "cap:cloud":            ["aws", "gcloud", "az", "kubectl", "helm", "terraform"],
}


def ssh_run(remote_cmd, timeout=90):
    try:
        r = subprocess.run(f"{SSH} {shlex.quote(remote_cmd)}", shell=True,
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""


def probe_containers():
    out = ssh_run('docker ps --format "{{.Names}}"', timeout=30)
    return sorted(l.strip() for l in out.splitlines() if l.strip().startswith("6v6-"))


def probe_tools():
    """One docker-exec per container: which TOOLS resolve + their path."""
    found = {}  # tool -> {container: path}
    tool_list = " ".join(dict.fromkeys(TOOLS))   # dedup, keep order
    for c in PROBE_CONTAINERS:
        inner = f'for t in {tool_list}; do p=$(command -v "$t" 2>/dev/null); [ -n "$p" ] && echo "$t|$p"; done'
        out = ssh_run(f"docker exec {c} sh -c {shlex.quote(inner)}", timeout=120)
        for line in out.splitlines():
            if "|" in line:
                t, p = line.split("|", 1)
                found.setdefault(t.strip(), {})[c] = p.strip()
    return found


def probe_services():
    svc = {}
    def rec(name, present, evidence):
        svc[name] = {"present": bool(present), "evidence": (evidence or "").strip()[:240]}

    o = ssh_run("docker exec 6v6-web sh -c " + shlex.quote(
        'grep -rhoE "SecRuleEngine +(On|Off|DetectionOnly)" /etc/apache2 /etc/modsecurity /usr/share/modsecurity* 2>/dev/null | sort | uniq -c'))
    rec("service:modsecurity", o.strip(), o or "no SecRuleEngine directive on 6v6-web")

    o = ssh_run("docker exec 6v6-siem sh -c " + shlex.quote(
        '/var/ossec/bin/wazuh-control status 2>/dev/null | head -3; ls /var/ossec/logs/alerts/alerts.json 2>/dev/null'))
    rec("service:wazuh", o.strip(), o or "no /var/ossec on 6v6-siem")

    o = ssh_run("docker exec 6v6-siem sh -c " + shlex.quote(
        'command -v suricata; ls -la /var/log/suricata/eve.json 2>/dev/null'))
    if not o.strip():
        o = ssh_run("docker exec 6v6-ips sh -c " + shlex.quote(
            'command -v suricata; ls -la /var/log/suricata/eve.json 2>/dev/null'))
    rec("service:suricata", o.strip(), o or "no suricata on 6v6-siem/6v6-ips")

    o = ssh_run("docker exec 6v6-ips sh -c " + shlex.quote('command -v nft && nft list tables 2>/dev/null | head'))
    rec("service:nftables", o.strip(), o or "no nft on 6v6-ips")
    return svc


def probe_targets(containers):
    """web/app targets: container present (docker ps) + reachability via attacker curl."""
    targets = {
        "target:juice-shop":  "6v6-juiceshop",
        "target:dvwa":        "6v6-dvwa",
        "target:neobank":     "6v6-neobank",
        "target:govportal":   "6v6-govportal",
        "target:mediforum":   "6v6-mediforum",
        "target:adminconsole":"6v6-adminconsole",
        "target:aicompanion": "6v6-aicompanion",
    }
    out = {}
    for cap, cname in targets.items():
        up = cname in containers
        out[cap] = {"present": up, "evidence": f"{cname} {'in docker ps' if up else 'NOT running'}"}
    return out


def main():
    containers = probe_containers()
    if not containers:
        print("[probe] 6v6@0.103 unreachable or no 6v6-* containers — aborting", file=sys.stderr)
        sys.exit(2)
    tools = probe_tools()
    services = probe_services()
    targets = probe_targets(containers)

    tool_entries = {}
    for t in dict.fromkeys(TOOLS):
        where = tools.get(t, {})
        tool_entries[t] = {"present": bool(where), "where": where}

    caps = {}
    for cap, members in CAP_CLASSES.items():
        present_members = [m for m in members if tools.get(m)]
        if present_members:
            ev = ", ".join(f"{m}@{','.join(tools[m])}" for m in present_members[:3])
        else:
            ev = (f"none of {members} found in {PROBE_CONTAINERS}")
        caps[cap] = {"present": bool(present_members), "from": present_members, "evidence": ev}

    inv = {
        "probed_at": datetime.datetime.utcnow().isoformat() + "Z",
        "infra": "6v6@192.168.0.103",
        "containers": containers,
        "capabilities": {**caps, **services, **targets},
        "tools": tool_entries,
    }
    OUT.write_text(json.dumps(inv, ensure_ascii=False, indent=2))
    present = [k for k, v in inv["capabilities"].items() if v["present"]]
    absent = [k for k, v in inv["capabilities"].items() if not v["present"]]
    print(f"[probe] wrote {OUT}")
    print(f"[probe] containers={len(containers)}  capabilities present={len(present)} absent={len(absent)}")
    if "--print" in sys.argv:
        print("\nPRESENT:", ", ".join(present))
        print("\nABSENT :", ", ".join(absent))
        print("\nTOOLS present:", ", ".join(t for t, v in tool_entries.items() if v["present"]))


if __name__ == "__main__":
    main()

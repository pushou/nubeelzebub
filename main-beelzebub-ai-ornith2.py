#!/usr/bin/env python3
"""
main-beelzebub-ai.py
Version Python de main-beelzebub-ai.nu — détections cyber défensives

Reproduit fidèlement toutes les sections du script Nushell original :
  1. Extraction SSH brute + HTTP
  2. Commandes de téléchargement (wget/curl/ftp/tftp)
  3. URLs de C2 extraites des commandes
  4. Détection persistence (cron / user / privilege escalation)
  5. Analyse des mots de passe compromis
  6. Score d'intensité par attaquant (multi-criteria)
  7. Domain fronting / DNS spoofing via TLS SNI
  8. Payloads HTTP (body analysis)
  9. Base64 decoding
 10. HTTP-only attackers (probes sans SSH)
 11. Timestamps premières attaques par IP

Usage : python3 main-beelzebub-ai.py [--logdir log] [--jsondir json]
"""

import argparse
import base64
import gzip
import json
import re
import sys
from pathlib import Path

import polars as pl


# ═══════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyse Beelzebub Honeypot — version AI (Nushell original)"
    )
    parser.add_argument("--logdir", default="log", help="Dossier des logs .gz (défaut : log)")
    parser.add_argument("--jsondir", default="json", help="Dossier de sortie JSON (défaut : json)")
    return parser.parse_args()

ARGS = parse_args()
LOGDIR = Path(ARGS.logdir)
JSONDIR = Path(ARGS.jsondir)


# ═══════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════

def load_gz_ndjson(path: Path) -> list[dict]:
    """Load a single .gz NDJSON file and return a list of records."""
    records = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


# ═══════════════════════════════════════════════
# 0. Chargement des fichiers de logs
# ═══════════════════════════════════════════════

filelist = sorted(LOGDIR.glob("beelzebub.json.*.gz"))
if not filelist:
    print(f"[ERREUR] Aucun fichier log trouvé dans {LOGDIR}/beelzebub.json.*.gz")
    sys.exit(1)

print(f"[INFO] {len(filelist)} fichier(s) log trouvé(s) dans {LOGDIR}/")

all_records = []
for i, path in enumerate(filelist, 1):
    print(f"  [{i}/{len(filelist)}] {path.name}")
    try:
        records = load_gz_ndjson(path)
        all_records.extend(records)
    except Exception as exc:
        print(f"  [WARN] Erreur chargement {path.name} : {exc}")

print(f"[INFO] {len(all_records)} enregistrements bruts chargés.")

df_all = pl.DataFrame(all_records) if all_records else pl.DataFrame()
df_all = df_all.unnest("event") if not df_all.is_empty() else pl.DataFrame()

# ═══════════════════════════════════════════════
# 1. Extraction SSH brute + HTTP
# ═══════════════════════════════════════════════

dfssh = (
    df_all
    .filter(pl.col("Protocol") == "SSH")
    .select([
        "User", "Password", "DateTime", "RemoteAddr",
        "Protocol", "Command", "SourceIp",
    ])
) if not df_all.is_empty() else pl.DataFrame()

dfhttp = (
    df_all
    .filter(pl.col("Protocol") == "HTTP")
    .select([
        "DateTime", "RemoteAddr", "Protocol", "SourceIp",
        "Headers", "Cookies", "UserAgent",
        "HostHTTPRequest", "Body", "HTTPMethod",
        "RequestURI", "TLSServerName",
    ])
) if not df_all.is_empty() else pl.DataFrame()

ssh_count = dfssh.height
http_count = dfhttp.height
print(f"[INFO] SSH events: {ssh_count} | HTTP events: {http_count}\n")


# ═══════════════════════════════════════════════
# 2. Commandes de téléchargement (wget/curl/ftp)
# ═══════════════════════════════════════════════

download_commands = (
    dfssh
    .filter(pl.col("Command").str.contains("wget|curl|ftp|tftp", literal=False))
    .select(["SourceIp", "Command", "DateTime"])
)


# ═══════════════════════════════════════════════
# 3. URLs de C2 extraites des commandes
# ═══════════════════════════════════════════════

urls = (
    dfssh
    .select(pl.col("Command"))
    .select(pl.col("Command").str.split(" ").explode().alias("token"))
    .group_by("token")
    .agg(pl.len().alias("count"))
    .filter(pl.col("token").str.contains("http://|https://|ftp://|tftp://", literal=False))
    .sort("count", descending=True)
)


# ═══════════════════════════════════════════════
# 4. Détection persistence mechanisms
# ═══════════════════════════════════════════════

def detect_pattern(df: pl.DataFrame, pattern: str) -> pl.DataFrame:
    """Filter rows matching a pattern and select relevant columns."""
    return (
        df
        .filter(pl.col("Command").str.contains(pattern, literal=False))
        .select(["SourceIp", "Command", "DateTime"])
    )

cron_persistence = detect_pattern(dfssh, "crontab|cron|/etc/cron")
user_modification = detect_pattern(dfssh, "useradd|usermod|userdel|passwd|adduser|addgroup|deluser|delgroup")
privilege_escalation = detect_pattern(dfssh, "sudo|chmod|chown|setuid|setgid|visudo")
system_modification = detect_pattern(dfssh, "/etc/passwd|/etc/shadow|/etc/sudoers|sshd_config|authorized_keys")
recon_commands = detect_pattern(dfssh, "uname|whoami|ifconfig|ip addr|hostname|netstat|lsof")


# ═══════════════════════════════════════════════
# 5. Analyse des mots de passe compromis
# ═══════════════════════════════════════════════

password_analysis = (
    dfssh
    .select("Password")
    .filter(
        pl.col("Password").is_not_null() &
        (pl.col("Password").str.strip_chars().str.len_chars() > 0)
    )
    .group_by("Password")
    .agg(pl.len().alias("count"))
    .sort("count", descending=True)
    .head(30)
)


# ═══════════════════════════════════════════════
# 6. Score d'intensité par attaquant (SourceIp)
# ═══════════════════════════════════════════════

SCORE_RULES = [
    {"category": "download",      "pattern": "wget|curl|ftp|tftp",      "pts": 2},
    {"category": "priv_esc",      "pattern": "chmod|chown|sudo|visudo", "pts": 3},
    {"category": "user_mgmt",     "pattern": "useradd|usermod|passwd|adduser", "pts": 4},
    {"category": "persistence",   "pattern": "crontab|cron",            "pts": 3},
    {"category": "shell_access",  "pattern": "/bin/sh|/bin/bash|/dev/tcp", "pts": 5},
]

all_scores = []
for rule in SCORE_RULES:
    matched = dfssh.filter(pl.col("Command").str.contains(rule["pattern"], literal=False))
    if not matched.is_empty():
        ip_counts = matched.get_column("SourceIp").value_counts()
        ip_counts = ip_counts.with_columns(
            pl.Series("category", [rule["category"]] * ip_counts.height),
            pl.Series("pts", [rule["pts"]] * ip_counts.height),
        )
        all_scores.append(ip_counts)

if all_scores:
    all_scores_df = pl.concat(all_scores)
    attack_scores = (
        all_scores_df
        .group_by("SourceIp")
        .agg([
            pl.col("pts").sum().alias("total_score"),
            pl.col("category").unique().str.join("; ").alias("categories"),
        ])
        .sort("total_score", descending=True)
    )
else:
    attack_scores = pl.DataFrame(
        schema={"SourceIp": pl.String, "total_score": pl.Int64, "categories": pl.String}
    )


# ═══════════════════════════════════════════════
# 7. Domain fronting / DNS spoofing
# ═══════════════════════════════════════════════

def detect_dns_anomalies(df: pl.DataFrame) -> list[dict]:
    """Detect domain fronting and DNS spoofing (SNI vs Host mismatch)."""
    # Fix: exclude empty strings — is_not_null() alone passes ""
    df_filtered = df.filter(
        (pl.col("TLSServerName").str.strip_chars().str.len_chars() > 0) |
        (pl.col("HostHTTPRequest").str.strip_chars().str.len_chars() > 0)
    ).select(["TLSServerName", "HostHTTPRequest", "SourceIp", "RequestURI", "DateTime"])

    anomalies = []
    for row in df_filtered.iter_rows(named=True):
        sni = (row.get("TLSServerName") or "").strip()
        host = (row.get("HostHTTPRequest") or "").strip()

        if sni and host and sni != host:
            # Only flag as anomaly if both fields have content AND differ
            if "google.com" in sni:
                anomalies.append({
                    "type": "DNS SPOOFING",
                    "SNI": sni, "Host": host,
                    "SourceIp": row.get("SourceIp", ""),
                    "RequestURI": row.get("RequestURI", ""),
                })
            elif "google.com" in host:
                anomalies.append({
                    "type": "DNS SPOOFING (host)",
                    "SNI": sni, "Host": host,
                    "SourceIp": row.get("SourceIp", ""),
                    "RequestURI": row.get("RequestURI", ""),
                })
            else:
                anomalies.append({
                    "type": "DOMAIN MISMATCH",
                    "SNI": sni, "Host": host,
                    "SourceIp": row.get("SourceIp", ""),
                })

    return anomalies

dns_anomalies = detect_dns_anomalies(dfhttp)


# ═══════════════════════════════════════════════
# 8. Payloads HTTP (body analysis)
# ═══════════════════════════════════════════════

PAYLOAD_PATTERN = re.compile(
    r"php|eval|base64_decode|shell_exec|passthru|system\(|/bin/sh|/bin/bash|cmd\.exe"
)

def detect_http_payloads(df: pl.DataFrame) -> list[dict]:
    """Detect suspicious HTTP payloads in request bodies."""
    payloads = []
    # Fix: exclude empty strings — is_not_null() passes "" as valid
    df_filtered = df.filter(pl.col("Body").str.strip_chars().str.len_chars() > 0).select([
        "Body", "SourceIp", "RequestURI", "HTTPMethod", "DateTime"
    ])

    for row in df_filtered.iter_rows(named=True):
        body = str(row.get("Body") or "")
        if PAYLOAD_PATTERN.search(body):
            payloads.append({
                "type": "PAYLOAD DETECTED",
                "Method": row.get("HTTPMethod", ""),
                "RequestURI": row.get("RequestURI", ""),
                "SourceIp": row.get("SourceIp", ""),
            })

    return payloads

http_payloads = detect_http_payloads(dfhttp)


# ═══════════════════════════════════════════════
# 9. Base64 decoding
# ═══════════════════════════════════════════════

def decode_b64_commands(df: pl.DataFrame, output_path: Path) -> list[dict]:
    """Decode base64 strings from commands."""
    decoded_results = []

    df_words = df.with_columns(
        pl.col("Command").str.split(" ").alias("words")
    ).explode("words").rename({"words": "word"})

    word_counts = (
        df_words.get_column("word")
        .value_counts()
        .sort("count", descending=True)
    )

    for row in word_counts.iter_rows(named=True):
        cmd = (row.get("word") or "").strip().strip("'")
        if not cmd:
            continue

        mod = len(cmd) % 4
        padded = cmd
        if mod == 2:
            padded = cmd + "=="
        elif mod == 3:
            padded = cmd + "="

        try:
            decoded_bytes = base64.b64decode(padded)
            decoded_str = decoded_bytes.decode("iso-8859-1", errors="replace")
            decoded_str = re.sub(r"[^\x20-\x7E\n\t]", ".", decoded_str)
            if len(decoded_str) > 10:
                decoded_results.append({
                    "Command": cmd,
                    "count": row.get("count", 0),
                    "longueur": len(cmd),
                    "decoded": decoded_str,
                })
        except Exception:
            continue

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(decoded_results, f, indent=2, ensure_ascii=False)
    print(f"[INFO] Payloads décodés sauvegardés : {output_path}")

    return decoded_results

decoded = decode_b64_commands(dfssh, JSONDIR / "decoded.json")


# ═══════════════════════════════════════════════
# 10. HTTP-only attackers (probes sans SSH)
# ═══════════════════════════════════════════════

ssh_ips = set(dfssh.get_column("SourceIp").str.strip_chars().unique().to_list())
http_ips = set(dfhttp.get_column("SourceIp").str.strip_chars().unique().to_list())
http_only_ips = http_ips - ssh_ips


# ═══════════════════════════════════════════════
# 11. Timestamps premières attaques par IP
# ═══════════════════════════════════════════════

first_seen = (
    dfssh
    .select(["SourceIp", "DateTime"])
    .sort("DateTime")
    .group_by("SourceIp")
    .agg([
        pl.col("DateTime").min().alias("first_seen"),
    ])
)


# ═══════════════════════════════════════════════
# PRINT SUMMARY
# ═══════════════════════════════════════════════

print("\n═══════════════════════════════════════════════")
print("  ANALYSE CYBER — BEELZEBUB HONEYPOT (amél.)")
print("═══════════════════════════════════════════════\n")

print(f"SSH events: {ssh_count}")
print(f"HTTP events: {http_count}\n")

print("--- TOP 10 IPs attaquants (SSH) ---")
top_ssh = (
    dfssh.get_column("SourceIp")
    .value_counts()
    .sort("count", descending=True)
    .head(10)
)
for row in top_ssh.iter_rows(named=True):
    print(f"  {row['SourceIp']:40s} {row['count']:>6d}")

print("\n--- TOP 20 mots de passe compromis ---")
for row in password_analysis.head(20).iter_rows(named=True):
    pwd = row["Password"] or "(null)"
    cnt = row["count"]
    print(f"  {pwd}: {cnt}")

print("\n--- Score d'intensité par IP (top 20) ---")
for row in attack_scores.head(20).iter_rows(named=True):
    print(f"  {row['SourceIp']:40s} score={row['total_score']:<4d}  cat={row['categories']}")

print("\n--- Persistence détectée (cron) ---")
print(f"  {cron_persistence.height} events")

print("\n--- Modifications utilisateurs ---")
print(f"  {user_modification.height} events")

print("\n--- Privilege escalation ---")
print(f"  {privilege_escalation.height} events")

print("\n--- Modifications système (passwd/shadow/sudoers) ---")
print(f"  {system_modification.height} events")

print("\n--- Reconnaissance système ---")
print(f"  {recon_commands.height} events")

print("\n--- Anomalies DNS (SNI vs Host mismatch) ---")
print(f"  {len(dns_anomalies)} anomalies")

print("\n--- Payloads HTTP suspects ---")
print(f"  {len(http_payloads)} payloads")

print("\n--- IPs HTTP-only (pas d'SSH associé) ---")
print(f"  {len(http_only_ips)} IPs")

print("\n--- Premières apparitions par IP (top 15) ---")
for row in first_seen.head(15).iter_rows(named=True):
    print(f"  {row['SourceIp']:40s} {row['first_seen']}")

print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
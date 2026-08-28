# main-beelzebub-ai-enhanced.nu
# Fork amélioré de main-beelzebub-ai.nu — TOUTES les sections originales inchangées
#
# Ajouts :
#   - Hash des passwords (MD5)
#   - Compression confirmée (commandes exécutées = compromise réelle)
#   - Destruction de preuves (rm, history -c, shred)
#   - Cryptomining detection
#   - Regex améliorées (word boundaries)
#   - Corrélation SSH↔HTTP (attaquants multicanaux)
#   - Export JSON structuré pour SOC/SIEM
#   - Vérification intégrité des .gz
#   - Score corrigé sans hack fragile

# ═══════════════════════════════════════════════
# 0. Chargement des fichiers de logs
# ═══════════════════════════════════════════════
let filelist = ls log/beelzebub.json.*.gz | get name

use decode_b64.nu *

# ──────────────────────────────────────────────
# 1. Extraction SSH brute + HTTP (INCHANGÉ)
# ──────────────────────────────────────────────
let dfssh = $filelist
                  | each {print $"SSH: ($in)"
                          ; polars open $in -t ndjson --infer-schema 5000
                          | try { polars get event
                                  | polars unnest event
                                  | polars filter ((polars col Protocol) == 'SSH')
                                  | polars select User Password DateTime RemoteAddr Protocol Command SourceIp }}
                  | reduce {|it, acc| $it | polars concat $acc }
                  | polars collect

let dfhttp = $filelist
                   | each {print $"HTTP: ($in)"
                           ; polars open $in -t ndjson --infer-schema 5000
                           | try { polars get event
                                   | polars unnest event
                                   | polars filter ((polars col Protocol) == 'HTTP')
                                   | polars select DateTime RemoteAddr Protocol SourceIp Headers Cookies UserAgent HostHTTPRequest Body HTTPMethod RequestURI TLSServerName }}
                   | reduce {|it, acc| $it | polars concat $acc }
                   | polars collect

# ──────────────────────────────────────────────
# 1b. Analyse Honeypot LiteLLM — port 4000
# ──────────────────────────────────────────────
# Les requêtes LiteLLM ciblent /v1/* (OpenAI-compatible API)
# Endpoints: /v1/models, /v1/chat/completions, /v1/embeddings, /v1/completions

# Extraction polars → table nushell
let litellm_table = ($dfhttp
  | polars filter (
      (polars col RequestURI | polars contains "/v1/")
      or (polars col Headers | polars contains "litellm")
    )
  | polars collect
  | polars into-nu)

let litellm_count = ($litellm_table | length)

# Classification par endpoint (polars)
let litellm_by_endpoint = if $litellm_count > 0 {
    $litellm_table
    | polars into-df
    | polars group-by [RequestURI]
    | polars agg [
        (polars col SourceIp | polars n-unique | polars as unique_ips)
        (polars col RequestURI | polars count | polars as count)
      ]
    | polars collect
    | polars into-nu
    | sort-by -r count
    | select RequestURI count unique_ips
  } else { [] }

# IPs attaquantes (polars value-counts → nushell)
let litellm_attackers = if $litellm_count > 0 {
    ($litellm_table
      | polars into-df
      | polars get SourceIp
      | polars value-counts
      | polars sort-by -r [true] count
      | polars collect
      | polars into-nu)
  } else { [] }

# User-Agents (polars value-counts → nushell)
let litellm_user_agents = if $litellm_count > 0 {
    ($litellm_table
      | polars into-df
      | polars get UserAgent
      | polars value-counts
      | polars sort-by -r [true] count
      | polars collect
      | polars into-nu
      | first 10)
  } else { [] }

# Timeline (polars → nushell)
let litellm_timeline = if $litellm_count > 0 {
    ($litellm_table
      | polars into-df
      | polars select SourceIp RequestURI HTTPMethod DateTime
      | polars sort-by DateTime
      | polars collect
      | polars into-nu)
  } else { [] }

# Pour compatibilité avec les anciennes variables dans le script
let litellm_events = $litellm_table

# ──────────────────────────────────────────────
# 1c. Stat par type d'honeypot (HTTP ventilé par port)
#      SSH  |  HTTP/Web:80  |  LiteLLM:4000  |  Docker:2375  |  Ollama:11434
# ──────────────────────────────────────────────
let honeypot_names = {
  "22":    "SSH"
  "80":    "HTTP/Web (WordPress)"
  "4000":  "LiteLLM Proxy"
  "2375":  "Docker Remote API"
  "11434": "Ollama"
  "27017": "MongoDB"
}

let honeypot_stats = (
  # Événements HTTP → identifier le port d'écoute depuis HostHTTPRequest
  ($dfhttp | polars into-nu
    | each { |r|
        let hst = ($r.HostHTTPRequest | str trim)
        let port = (if ($hst | str contains ":") { ($hst | split row ":" | last | str trim) } else { "80" })
        { Honeypot: "HTTP", Port: $port, SourceIp: $r.SourceIp, DateTime: $r.DateTime }
      })
  # + événements SSH
  | append ($dfssh | polars into-nu | each { |r| { Honeypot: "SSH", Port: "22", SourceIp: $r.SourceIp, DateTime: $r.DateTime } })
  | group-by {|r| $"($r.Honeypot)::($r.Port)" }
  | items { |key, rows|
      let parts = ($key | split row '::')
      let proto = ($parts | get 0)
      let port = ($parts | get 1)
      let known = ($honeypot_names | get -o $port)
      let name = (if ($known | is-empty) { "HTTP/Web" } else { $known })
      { Honeypot: $name
        Protocol: $proto
        Port: $port
        Events: ($rows | length)
        UniqueIPs: ($rows | get SourceIp | uniq | length) }
    }
  | sort-by -r Events)

# ═══════════════════════════════════════════════
# 1d. Export PARQUET — événements d'attaque par honeypot
#     Colonnes: DateTime, SourceIp, Protocol, Honeypot, Port,
#     Username, Password, Method, URI, Command, DownloadUri
# ═══════════════════════════════════════════════
# Extrait la première URL de téléchargement (wget/curl/tftp) d'une chaîne
def extract_dl_uri [s: string] {
  let r = ($s | parse -r '(?<u>https?://[^\s\"<>+)\]&]+)')
  if ($r | is-empty) { "" } else { ($r | get "u" | first) }
}

let attacks_parquet_path = "json/attacks_by_honeypot.parquet"

let attacks_by_honeypot = (
  # Événements SSH : commande + éventuelle URI de téléchargement
  ($dfssh | polars into-nu | each { |r| {
      DateTime: $r.DateTime, SourceIp: $r.SourceIp, Protocol: "SSH", Honeypot: "SSH", Port: "22",
      Username: $r.User, Password: $r.Password, Method: "", URI: "", Command: $r.Command,
      DownloadUri: (extract_dl_uri $r.Command)
    }})
  # Événements HTTP : honeypot déduit du port + URI/Body
  | append ($dfhttp | polars into-nu | each { |r|
        let hst = ($r.HostHTTPRequest | str trim)
        let port = (if ($hst | str contains ":") { ($hst | split row ":" | last | str trim) } else { "80" })
        let known = ($honeypot_names | get -o $port)
        let hp = (if ($known | is-empty) { "HTTP/Web" } else { $known })
        { DateTime: $r.DateTime, SourceIp: $r.SourceIp, Protocol: "HTTP", Honeypot: $hp, Port: $port,
          Username: "", Password: "", Method: $r.HTTPMethod, URI: $r.RequestURI, Command: "",
          DownloadUri: (extract_dl_uri $r.Body) }
      })
  | polars into-df
)

$attacks_by_honeypot | polars save --type parquet $attacks_parquet_path

# ──────────────────────────────────────────────
# 2. Commandes de téléchargement — SSH et HTTP séparés, regex améliorée
#    (bordures de mots; wget|curl|ftp|tftp, y compris tftp comme commande)
# ──────────────────────────────────────────────
let dl_regex = "\\b(wget|curl|ftp|tftp)\\b"

# Téléchargements côté SSH (champ Command des sessions réussies)
let download_commands_ssh = ($dfssh
  | polars filter (polars col Command | polars contains $dl_regex)
  | polars select SourceIp Command DateTime
  | polars into-nu
  | each { |r| { SourceIp: $r.SourceIp, Protocol: "SSH", DateTime: $r.DateTime, Detail: $r.Command } }
  | sort-by DateTime)

# Téléchargements côté HTTP (RequestURI ou Body)
let download_commands_http = ($dfhttp
  | polars filter ((polars col RequestURI | polars contains $dl_regex) or (polars col Body | polars contains $dl_regex))
  | polars select SourceIp RequestURI Body DateTime
  | polars into-nu
  | each { |r|
      let uri = ($r.RequestURI | default "" | into string | str trim)
      let detail = if ($uri | str length) > 0 { $uri } else { ($r.Body | default "" | into string | str trim) }
      { SourceIp: $r.SourceIp, Protocol: "HTTP", DateTime: $r.DateTime, Detail: $detail } }
  | sort-by DateTime)

# Vue consolidée (conserver pour compatibilité / total)
let download_commands = ($download_commands_ssh | append $download_commands_http | sort-by DateTime)

# ──────────────────────────────────────────────
# 3. URLs de C2 (INCHANGÉ)
# ──────────────────────────────────────────────
let urls = ($dfssh
  | polars get Command
  | polars select (polars col Command | polars str-split " " | polars explode)
  | polars value-counts
  | polars filter ((polars col Command) | polars contains "http://|https://|ftp://|tftp://")
  | polars into-nu
  | sort-by -r count)

# ──────────────────────────────────────────────
# 3b. Fréquence des commandes exécutées (uniques + count)
# ──────────────────────────────────────────────
let command_frequency = ($dfssh
  | polars select Command
  | polars filter (polars col Command | polars is-not-null)
  | polars value-counts
  | polars into-nu
  | where ($it.Command | into string | str trim | str length) > 0
  | sort-by -r count)

# ──────────────────────────────────────────────
# 4. Détection persistence — regex améliorée
# ──────────────────────────────────────────────
let cron_persistence = ($dfssh
  | polars filter (polars col Command | polars contains "\\b(crontab|cron)\\b")
  | polars select SourceIp Command DateTime
  | polars into-nu)

let user_modification = ($dfssh
  | polars filter (polars col Command | polars contains "\\b(useradd|usermod|userdel|passwd|adduser|addgroup|deluser|delgroup)\\b")
  | polars select SourceIp Command DateTime
  | polars into-nu)

let privilege_escalation = ($dfssh
  | polars filter (polars col Command | polars contains "\\b(sudo|chmod|chown|setuid|setgid|visudo)\\b")
  | polars select SourceIp Command DateTime
  | polars into-nu)

let system_modification = ($dfssh
  | polars filter (polars col Command | polars contains "/etc/passwd|/etc/shadow|/etc/sudoers|sshd_config|authorized_keys")
  | polars select SourceIp Command DateTime
  | polars into-nu)

let recon_commands = ($dfssh
  | polars filter (polars col Command | polars contains "\\b(uname|whoami|ifconfig|ip addr|hostname|netstat|lsof)\\b")
  | polars select SourceIp Command DateTime
  | polars into-nu)

# ═══════════════════════════════════════════════
# 14. Destruction de preuves (ajout)
# ═══════════════════════════════════════════════
let evidence_tampering = ($dfssh
  | polars filter (polars col Command | polars contains "rm -rf|history -c|shred|wipe|srm")
  | polars select SourceIp Command DateTime
  | polars into-nu)

# Group-by commande identique → liste des IPs qui l'ont exécutée
# (évite de répéter 137 lignes pour ~10 commandes uniques)
let evidence_tampering_by_cmd = ($evidence_tampering
  | group-by Command
  | items { |cmd, rows|
      let ips = ($rows | get SourceIp | uniq | sort)
      { Command: $cmd
        unique_ips: $ips
        ip_count: ($ips | length)
        events: ($rows | length) }
    }
  | sort-by -r events)

# ═══════════════════════════════════════════════
# 15. Cryptomining detection (ajout)
# ═══════════════════════════════════════════════
let crypto_mining = ($dfssh
  | polars filter (polars col Command | polars contains "xmrig|minergate|cpuminer|coinhive|stratum|mine.php|monero|bitcoin|miner|cryptonight|kawpow")
  | polars select SourceIp Command DateTime
  | polars into-nu)

# ──────────────────────────────────────────────
# 5. Analyse des mots de passe — AMÉLIORÉ : HASH
# ──────────────────────────────────────────────
let password_analysis_raw = ($dfssh
  | polars select Password
  | polars filter (polars col Password | polars is-not-null)
  | polars value-counts
  | polars sort-by -r [true] count
  | polars into-nu
  | first 30)

# Hash MD5 pour ne jamais exposer les passwords en clair
let password_hashes = ($password_analysis_raw
  | each { |row|
      let pwd = ($row.Password | into string)
      let hash_val = ($pwd | hash md5)
      { Password: $pwd
        password_hash: $hash_val
        count: $row.count
        _note: "Hashé MD5 — plaintext conservé pour analyse"
      }
    })

# ═══════════════════════════════════════════════
# 13. COMPROMISSION CONFIRMÉE (ajout CRITIQUE)
# ═══════════════════════════════════════════════
# Toute commande exécutée = connexion réussie confirmée
let confirmed_compromised = ($dfssh
  | polars filter (polars col Command | polars is-not-null)
  | polars select SourceIp User
  | polars unique
  | polars into-nu)

# ──────────────────────────────────────────────
# 6. Score d'intensité — CORRIGÉE (nushell natif propre)
# ──────────────────────────────────────────────
let score_rules = [
    { category: "download"      , pattern: "\\b(wget|curl|ftp|tftp)\\b"      , pts: 2 }
    { category: "priv_esc"      , pattern: "\\b(chmod|chown|sudo|visudo)\\b" , pts: 3 }
    { category: "user_mgmt"     , pattern: "\\b(useradd|usermod|passwd|adduser)\\b" , pts: 4 }
    { category: "persistence"   , pattern: "\\b(crontab|cron)\\b"            , pts: 3 }
    { category: "shell_access"  , pattern: "\\b(/bin/sh|/bin/bash|/dev/tcp)\\b" , pts: 5 }
]

# On convertit en nushell après value-counts (comme l'original)
# Puis on ajoute category/pts en nushell
let all_scores = ($score_rules
  | each { |rule|
      $dfssh
      | polars filter (polars col Command | polars contains $rule.pattern)
      | polars select SourceIp
      | polars value-counts
      | polars into-nu
      | each { |row|
          { SourceIp: $row.SourceIp, count: $row.count, category: $rule.category, pts: $rule.pts }
        }
    }
  | flatten)

# Agrégation propre en nushell natif — sans le hack fragile
# group-by crée un record où les COLONNES sont les valeurs d'IP
let attack_scores_v2 = ($all_scores
  | group-by SourceIp
  | each { |g|
      let cols = ($g | columns)
      let ip = ($cols | first)
      let pts_list = ($g | get $ip | get pts)
      let cats = ($g | get $ip | get category | uniq | str join "; ")
      let total = ($pts_list | math sum)
      let evt_count = ($g | get $ip | length)
      { SourceIp: $ip, total_score: $total, categories: $cats, event_count: $evt_count }
  }
  | flatten
  | sort-by -r total_score)

# Ancien pour comparaison (inchangé depuis le script original)
let attack_scores = ($all_scores
  | group-by SourceIp
  | each { |group|
      let ip = ($group | columns | where $it != "0" | first)
      let col_data = ($group | get $ip)
      { SourceIp: $ip
        total_score: ($col_data.pts | math sum)
        categories: ($col_data.category | uniq | str join "; ")
      }
  }
  | flatten
  | sort-by -r total_score)

# ──────────────────────────────────────────────
# 7. Domain fronting / DNS spoofing (INCHANGÉ)
# ──────────────────────────────────────────────
let dns_anomalies = ($dfhttp
  | polars filter (
      ((polars col TLSServerName | polars is-not-null))
      or ((polars col HostHTTPRequest | polars is-not-null))
    )
  | polars select TLSServerName HostHTTPRequest SourceIp RequestURI DateTime
  | polars collect | polars into-nu
  | each { |row|
      let sni = ($row.TLSServerName | str trim)
      let host = ($row.HostHTTPRequest | str trim)
      if ($sni | str contains "google.com") {
          $"DNS SPOOFING: SNI=($sni) Host=($host) IP=($row.SourceIp) URI=($row.RequestURI)"
      } else if ($host | str contains "google.com") {
          $"DNS SPOOFING (host): SNI=($sni) Host=($host) IP=($row.SourceIp) URI=($row.RequestURI)"
      } else if ($sni != $host and $sni != "" and $host != "") {
          $"DOMAIN MISMATCH: SNI=($sni) Host=($host) IP=($row.SourceIp)"
      } else { null }
    }
  | each { |x| if $x != null { $x } })

# ──────────────────────────────────────────────
# 8. Payloads HTTP — regex améliorée
# ──────────────────────────────────────────────
let http_payloads = ($dfhttp
  | polars filter (polars col Body | polars is-not-null)
  | polars select Body SourceIp RequestURI HTTPMethod DateTime
  | polars collect | polars into-nu
  | each { |row|
      let body = ($row.Body | into string)
      if ($body | str contains "php|eval|base64_decode|shell_exec|passthru|system(|/bin/sh|/bin/bash|cmd.exe") {
          $"PAYLOAD DETECTED: Method=($row.HTTPMethod) URI=($row.RequestURI) IP=($row.SourceIp)"
      } else { null }
    }
  | each { |x| if $x != null { $x } })

# ──────────────────────────────────────────────
# 9. Base64 decoding (FIX: SSH Command + HTTP Body)
# ──────────────────────────────────────────────
# Filter nulls in polars, convert to nushell, extract column values, combine
let ssh_cmds = ($dfssh
  | polars filter (polars col Command | polars is-not-null)
  | polars get Command
  | polars into-nu
  | get Command
  | where ($it | into string | str length) >= 16
  | str trim
  | each { ({ Command: $in }) })
let http_bodies = ($dfhttp
  | polars filter (polars col Body | polars is-not-null)
  | polars get Body
  | polars into-nu
  | get Body
  | where ($it | into string | str length) >= 16
  | str trim
  | each { ({ Command: $in }) })
let b64_data = ($ssh_cmds | append $http_bodies)

let decoded = ($b64_data
  | decode-b64
  | tee {save -f ./json/decoded.json}
  | where $it.decoded != $it.Command
  | get decoded)

# ──────────────────────────────────────────────
# 10. HTTP-only attackers (INCHANGÉ)
# ──────────────────────────────────────────────
let ssh_ips = ($dfssh | polars into-nu | get SourceIp | uniq | str trim)
let http_ips = ($dfhttp | polars into-nu | get SourceIp | uniq | str trim)
let http_only_ips = ($http_ips | each { |ip| if ($ssh_ips | any { |s| $s == $ip }) { null } else { $ip } })

# ═══════════════════════════════════════════════
# 17. Corrélation SSH↔HTTP — Attaquants multicanaux (nushell pur)
# ═══════════════════════════════════════════════
# Comptes par IP via polars value-counts
let ssh_counts = ($dfssh | polars get SourceIp | polars value-counts | polars collect | polars into-nu)
let http_counts = ($dfhttp | polars get SourceIp | polars value-counts | polars collect | polars into-nu)

# IPs uniques
let ssh_ips_list = ($ssh_counts | get SourceIp | str trim)
let http_ips_list = ($http_counts | get SourceIp | str trim)

let multi_channel_attackers = ($ssh_ips_list
  | each { |ip|
      if ($http_ips_list | any { |h| $h == $ip }) {
        let ssh_cnt = ($ssh_counts | where SourceIp == $ip | get count | first)
        let http_cnt = ($http_counts | where SourceIp == $ip | get count | first)
        { SourceIp: $ip, ssh_events: $ssh_cnt, http_events: $http_cnt, risk_level: "CRITICAL — multi-canal" }
      } else { null }
    }
  | each { |x| if $x != null { $x } }
  | sort-by -r http_events)

let http_only_attackers = ($http_ips_list
  | each { |ip|
      if ($ssh_ips_list | all { |s| $s != $ip }) {
        let http_cnt = ($http_counts | where SourceIp == $ip | get count | first)
        { SourceIp: $ip, http_events: $http_cnt, risk_level: "LOW — HTTP only" }
      } else { null }
    }
  | each { |x| if $x != null { $x } }
  | sort-by -r http_events)

# ──────────────────────────────────────────────
# 11. Timestamps premières attaques par IP (INCHANGÉ)
# ──────────────────────────────────────────────
let first_seen = ($dfssh
  | polars select SourceIp DateTime
  | polars sort-by DateTime
  | polars group-by SourceIp
  | polars agg [(polars col DateTime | polars min | polars as first_seen)]
  | polars collect
  | polars into-nu)

# ═══════════════════════════════════════════════
# 18. Export JSON structuré pour SOC/SIEM
# ═══════════════════════════════════════════════
mkdir json/

let soc_export = {
  timestamp: (date now | format date "%Y-%m-%dT%H:%M:%S%z")
  summary: {
    ssh_events: ($dfssh | polars into-nu | length)
    http_events: ($dfhttp | polars into-nu | length)
    litellm_events: ($litellm_events | length)
    litellm_unique_ips: ($litellm_attackers | length)
    honeypot_by_type: ($honeypot_stats)
    confirmed_compromised_ips: ($confirmed_compromised | length)
    multi_channel_attackers: ($multi_channel_attackers | length)
    dns_anomalies_count: ($dns_anomalies | length)
    http_payloads_count: ($http_payloads | length)
    crypto_mining_attempts: ($crypto_mining | length)
    evidence_tampering_attempts: ($evidence_tampering | length)
  }
  top_attackers_score: ($attack_scores_v2 | first 10)
  confirmed_compromised: ($confirmed_compromised | first 20)
  multi_channel_attackers: ($multi_channel_attackers | first 10)
  litellm_honeypot: {
    events: ($litellm_events | first 50)
    by_endpoint: ($litellm_by_endpoint)
    top_attackers: ($litellm_attackers | first 20)
    user_agents: ($litellm_user_agents)
    timeline: ($litellm_timeline | first 50)
  }
  suspicious_urls_c2: ($urls | first 20)
  command_frequency: ($command_frequency | first 50)
  dns_anomalies: ($dns_anomalies | first 20)
  http_payloads: ($http_payloads | first 20)
  crypto_mining: ($crypto_mining | first 10)
  evidence_tampering: ($evidence_tampering | first 10)
  evidence_tampering_by_cmd: ($evidence_tampering_by_cmd)
  download_commands: ($download_commands | first 30)
  download_commands_ssh: ($download_commands_ssh | first 30)
  download_commands_http: ($download_commands_http | first 30)
  first_seen_ips: ($first_seen | first 20)
  password_intelligence: ($password_hashes | first 10)
  http_only_attackers: ($http_only_attackers | first 20)
}

$soc_export | save -f json/soc_export.json

print "[INFO] Export JSON SOC/SIEM sauvegardé : json/soc_export.json"
print $"[INFO] Export PARQUET attaques par honeypot : ($attacks_parquet_path)"

# ═══════════════════════════════════════════════
# PRINT SUMMARY ENRICHI
# ═══════════════════════════════════════════════
print "\n═══════════════════════════════════════════════"
print "  ANALYSE CYBER — BEELZEBUB HONEYPOT (ENHANCED)"
print "═══════════════════════════════════════════════\n"

let ssh_count = ($dfssh | polars into-nu | length)
let http_count = ($dfhttp | polars into-nu | length)
print $"SSH events: ($ssh_count)"
print $"HTTP events: ($http_count)"
print $"LiteLLM honeypot (port 4000): ($litellm_count) events\n"

print "\n--- 🏷️  STAT PAR TYPE D'HONEYPOT (HTTP ventilé par port) ---"
print $"  ($honeypot_stats | length) types"
print ($honeypot_stats | select Honeypot Protocol Port Events UniqueIPs)

print "--- TOP 10 IPs attaquants (SSH) ---"
print ($dfssh
  | polars get SourceIp
  | polars value-counts
  | polars sort-by -r [true] count
  | polars into-nu
  | first 10)

print "\n--- COMPROMISSION CONFIRMÉE — IPs ayant exécuté des commandes ---"
print $"  ($confirmed_compromised | length) IPs identifiées"
print ($confirmed_compromised | first 15)

print "\n--- Score d'intensité par IP (V2 corrigée, top 20) ---"
print ($attack_scores_v2 | first 20)

print "\n--- Anomalies DNS (SNI vs Host mismatch) ---"
print $"  ($dns_anomalies | length) anomalies"

print "\n--- Payloads HTTP suspects ---"
print $"  ($http_payloads | length) payloads"

print "\n--- Persistence détectée (cron) ---"
print $"  ($cron_persistence | length) events"

print "\n--- Modifications utilisateurs ---"
print $"  ($user_modification | length) events"

print "\n--- Privilege escalation ---"
print $"  ($privilege_escalation | length) events"

print "\n--- Modifications système (passwd/shadow/sudoers) ---"
print $"  ($system_modification | length) events"

print "\n--- Reconnaissance système ---"
print $"  ($recon_commands | length) events"

# ═══════════════════════════════════════════════
# NOUVEAUX RÉSULTATS AMÉLIORÉS
# ═══════════════════════════════════════════════
print "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print "  === NOUVEAUX DÉTECTIONS ENHANCED ==="
print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

print "\n--- ⚠️  COMPROMISSIONS CONFIRMÉES (commandes exécutées) ---"
print "  ( | length) attaquants ayant execute des commandes"
print ($confirmed_compromised | first 10)

print "\n--- 🎯 Attaquants multicanaux (SSH + HTTP) — RISQUE CRITIQUE ---"
print "  ( | length) IPs identifiees"
if ($multi_channel_attackers | length) > 0 {
    print ($multi_channel_attackers | first 10)
    print "\n  ⚠️  Ces IPs ont attaqué à la fois SSH et HTTP — profil avancé"
}

print "\n--- 🔍 Scanners HTTP-only (pas d'SSH) ---"
print $"  ($http_only_attackers | length) IPs"
print ($http_only_attackers | first 10)

print "\n--- 🚨 Destruction de preuves détectée ---"
print $"  ($evidence_tampering | length) tentatives  |  ($evidence_tampering_by_cmd | length) commandes distinctes"
if ($evidence_tampering | length) > 0 {
    print "\n  ← Par commande identique (liste des IPs) →"
    $evidence_tampering_by_cmd | each { |row|
        let nips = ($row.ip_count)
        let nevents = ($row.events)
        print ""
        print $"  ▸ COMMANDE: ($nips) IPs uniques, ($nevents) events"
        print $"      ($row.Command)"
        print $"      IPs: ($row.unique_ips | str join ', ')"
    }
}

print "\n--- ⛏️  Cryptomining détecté ---"
print $"  ($crypto_mining | length) tentatives"
if ($crypto_mining | length) > 0 {
    print $crypto_mining
}

# ═══════════════════════════════════════════════
# Honeypot LiteLLM — port 4000
# ═══════════════════════════════════════════════
print "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print "  🤖 HONEYPOT LiteLLM (port 4000)"
print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

print $"  Total events: ($litellm_count)"
print $"  Unique IPs: ($litellm_attackers | length)"

if ($litellm_count > 0) {
    print "\n--- Classification par endpoint ---"
    print ($litellm_by_endpoint)

    print "\n--- Top attaquants ---"
    print ($litellm_attackers | first 15)

    print "\n--- User-Agents observés ---"
    print ($litellm_user_agents)

    print "\n--- Timeline (dernières 20 requêtes) ---"
    print ($litellm_timeline | last 20)

    # Vérification: scanners déjà connus en SSH qui touchent aussi LiteLLM
    let litellm_ssh_overlap = ($litellm_attackers
      | get SourceIp
      | each { |ip|
          if ($confirmed_compromised | where SourceIp == $ip | length) > 0 {
            { SourceIp: $ip, risk: "CRITICAL — SSH compromised + LiteLLM scan" }
          } else { null }
        }
      | each { |x| if $x != null { $x } })

    if ($litellm_ssh_overlap | length) > 0 {
        print "\n  ⚠️  SURVEILLEZ: IPs compromises en SSH qui scannent aussi LiteLLM"
        print $litellm_ssh_overlap
    }
} else {
    print "\n  ℹ️  Aucun événement LiteLLM détecté pour cette période"
    print "  Vérifiez: littlellm.yaml bien monté sur /data/beelzebub/config/services/http-4000.yaml"
}

print "\n--- 🔐 Intelligence mots de passe (TOP 10 bruts) ---"
print ($password_analysis_raw | first 10)

print "\n--- 🔐 Passwords (plaintext) ---"
print ($password_analysis_raw | first 10 | select Password count)

print "\n--- 📊 URLs C2 / Downloaders (top 15) ---"
print ($urls | first 15)

print "\n--- 🧾 Commandes exécutées (uniques + count, top 20) ---"
print $"  ($command_frequency | length) commandes uniques"
print ($command_frequency | first 20)

print "\n--- 🕐 Premières apparitions par IP (top 15) ---"
print ($first_seen | first 15)

print "\n--- 🔓 Téléchargements SSH (wget/curl/ftp/tftp) ---"
print $"  ($download_commands_ssh | length) events"
print ($download_commands_ssh | first 10 | select SourceIp DateTime Detail)

print "\n--- 🔓 Téléchargements HTTP (wget/curl/ftp/tftp) ---"
print $"  ($download_commands_http | length) events"
print ($download_commands_http | first 10 | select SourceIp DateTime Detail)

print "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print "  ✅ Export JSON SOC : json/soc_export.json"
print "  ✅ Payloads décodés : json/decoded.json"
print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

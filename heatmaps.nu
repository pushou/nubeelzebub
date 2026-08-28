#!/usr/bin/env nu
# ═══════════════════════════════════════════════════════════════
# Heatmaps xan — attaques par honeypot (Beelzebub)
#
# « Meilleure façon » (workflow) :
#   1. Pré-agréger en petites tables numériques (rapide, évite le
#      plot catégoriel lent de xan).
#   2. `xan matrix count` / `xan matrix corr` pour construire la matrice.
#   3. `xan heatmap` avec un gradient et, si besoin, -N (nombres) et
#      -D (diverging) pour les corrélations.
#
# ⚠️  IMPORTANT : xan heatmap n'affiche les cellules qu'EN TERMINAL
#   (TTY interactif). Lancé dans un script/pipe, la grille sort vide.
#   Ouvrez un terminal interactif et lancez :  nu heatmaps.nu
# ═══════════════════════════════════════════════════════════════

# À lancer depuis la RACINE du projet (là où se trouvent json/ et le parquet).
const CSV  = "json/charts/attacks.csv"            # export parquet -> csv
const PARQ = "json/attacks_by_honeypot.parquet"
const OUT  = "json/charts"

# ── 0. Parquet -> CSV (si absent) ───────────────────────────────
if not ($CSV | path exists) {
  polars open $PARQ | polars into-nu | to csv | save -f $CSV
  print $"[INFO] $CSV régénéré depuis $PARQ"
}

# ── Helper : matrice cross-tab col1 × col2 limitée au top-N col1 ──
def cross_view [col1: string, col2: string, n: int, name: string, title: string] {
  # top-N valeurs de col1 par nombre d'événements
  let top = (xan groupby $col1 "count() as n" $CSV | xan top n -l $n | xan select $col1 | lines | skip 1 | str trim)

  # filtre le CSV : col1 dans le top et col2 non vide
  let filtered = ($OUT + "/" + $name + "_filtered.csv")
  open $CSV
  | where {|r| (($r | get $col1) in $top) and (($r | get $col2 | into string | str trim) != "")}
  | to csv | save -f $filtered

  let out = ($OUT + "/" + $name + "_matrix.csv")
  xan matrix count $col1 $col2 $filtered | save -f $out

  print ("\n===== " + $title + " (top " + ($n | into string) + ") =====")
  print "(xan matrix count " + $col1 + " " + $col2 + ") | xan heatmap -S 4 -N --gradient viridis --normalize col"
  xan heatmap -S 4 -N --gradient viridis --normalize col $out
}

# ── 1. Matrice top attaquants × ports (comptage) ────────────────
cross_view SourceIp Port 15 "ipxport" "HEATMAP 1 : TOP ATTAQUANTS × PORTS"

# ── 2. Features par IP + matrice de corrélation ─────────────────
nu -c 'let e = (open json/charts/attacks.csv | where SourceIp != "" | group-by SourceIp | items {|k,v| {ip: $k, n_events: ($v|length)}});
let p = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Port | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_ports: ($v|length)}});
let c = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Command | where Command != "" | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_cmds: ($v|length)}});
let m = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Method | where Method != "" | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_methods: ($v|length)}});
let h = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Honeypot | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_honeypots: ($v|length)}});
$e | join $p ip -l | join $c ip -l | join $m ip -l | join $h ip -l | each {|r|
  { ip: $r.ip, n_events: ($r.n_events? | default 0), n_ports: ($r.n_ports? | default 0), n_cmds: ($r.n_cmds? | default 0), n_methods: ($r.n_methods? | default 0), n_honeypots: ($r.n_honeypots? | default 0) }
} | to csv' | save -f ($OUT + "/features_per_ip.csv")

xan select n_events,n_ports,n_cmds,n_methods,n_honeypots ($OUT + "/features_per_ip.csv") | xan matrix corr | save -f ($OUT + "/corr.csv")

print "\n===== HEATMAP 2 : CORRÉLATION FEATURES PAR IP (diverging) ====="
print "xan matrix corr (features) | xan heatmap -S 5 -N -D"
xan heatmap -S 5 -N -D ($OUT + "/corr.csv")

# ── 3. Vues cross-tab complémentaires ────────────────────────────
cross_view SourceIp Honeypot 15 "ipxhoneypot" "HEATMAP 3 : TOP ATTAQUANTS × HONEYPOTS"
cross_view Honeypot Port 10 "honeypotxport" "HEATMAP 4 : HONEYPOTS × PORTS"

print "\n✅ Terminé — les cellules ne s'affichent qu'en terminal interactif (TTY)."

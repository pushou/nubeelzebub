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

# ── 1. Matrice top attaquants × ports (comptage) ────────────────
# colonnes de attacks.csv : 1=DateTime 2=SourceIp 5=Port
xan groupby SourceIp "count() as n" $CSV | xan top n -l 15 | xan select SourceIp | lines | skip 1 | save -f ($OUT + "/top15.txt")

# filtre les top IPs et garde (SourceIp, Port)
awk -F, '
  NR==FNR { if (FNR>1) top[$1]=1; next }
  FNR==1  { print "SourceIp,Port"; next }
  { if (($2 in top) && ($2 != "")) print $2 "," $5 }
' ($OUT + "/top15.txt") $CSV | save -f ($OUT + "/ip_port.csv")

xan matrix count SourceIp Port ($OUT + "/ip_port.csv") | save -f ($OUT + "/ipxport_matrix.csv")

# ── 2. Features par IP + matrice de corrélation ─────────────────
nu -c 'let e = (open json/charts/attacks.csv | where SourceIp != "" | group-by SourceIp | items {|k,v| {ip: $k, n_events: ($v|length)}});
let p = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Port | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_ports: ($v|length)}});
let c = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Command | where Command != "" | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_cmds: ($v|length)}});
let m = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Method | where Method != "" | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_methods: ($v|length)}});
let h = (open json/charts/attacks.csv | where SourceIp != "" | select SourceIp Honeypot | uniq | group-by SourceIp | items {|k,v| {ip: $k, n_honeypots: ($v|length)}});
$e | join $p ip -l | join $c ip -l | join $m ip -l | join $h ip -l | each {|r|
  { ip: $r.ip, n_events: ($r | get -i n_events | default 0), n_ports: ($r | get -i n_ports | default 0), n_cmds: ($r | get -i n_cmds | default 0), n_methods: ($r | get -i n_methods | default 0), n_honeypots: ($r | get -i n_honeypots | default 0) }
} | to csv' | save -f ($OUT + "/features_per_ip.csv")

xan select n_events,n_ports,n_cmds,n_methods,n_honeypots ($OUT + "/features_per_ip.csv") | xan matrix corr | save -f ($OUT + "/corr.csv")

# ── 3. Rendu heatmaps (interactif) ──────────────────────────────
print "\n===== HEATMAP 1 : TOP ATTAQUANTS × PORTS (comptage) ====="
print "xan matrix count SourceIp Port ip_port.csv | xan heatmap -S 4 -N --gradient viridis --normalize col"
xan heatmap -S 4 -N --gradient viridis --normalize col ($OUT + "/ipxport_matrix.csv")

print "\n===== HEATMAP 2 : CORRÉLATION FEATURES PAR IP (diverging) ====="
print "xan matrix corr (features) | xan heatmap -S 5 -N -D"
xan heatmap -S 5 -N -D ($OUT + "/corr.csv")

print "\n✅ Terminé — les cellules ne s'affichent qu'en terminal interactif (TTY)."

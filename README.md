# nubeelzebub
NuShell scripts to analyse beelzebug json outputs
Beelzebub json logs must be in ./log in gz format


## extract to json (output ./json)
nu main-beel.nu

## full log view
open json/beel.json | explore

## frequency diagram
open beelfreq.json|first 50|to csv|xan hist -R

## read decoded base64 (who begin with echo)
open json/base64.json
open json/base64.json|get decoded|less


## group-by SourceIP
polars open ./json/beel.json --infer-schema 50000|polars group-by SourceIp|polars agg {Commandes:(polars col Command|polars unique  --subset [Command]) Users: (polars col User|polars unique)}|polars collect


## group-by User
polars open ./json/beel.json --infer-schema 50000|polars group-by User|polars agg {Commandes:(polars col Command|polars unique  --subset [Command]) AdresseIP: (polars col SourceIp|polars unique)}|polars collect


## filters command that contains ...
polars open ./json/beel.json --infer-schema 50000|polars filter ((polars col Command|polars contains "uname|echo|wget|export|ftp|curl"))


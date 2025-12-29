# nubeelzebub
NuShell scripts to analyse beelzebug json outputs
Beelzebub json logs must be in ./log in gz format


## extract to json (output ./json)
nu main-beel.nu

## full log view
open json/beel.json | explore

## read decoded base64 (who begin with echo)
open json/base64.json
open json/base64.json|get decoded|less





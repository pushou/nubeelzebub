# nubeelzebub
NuShell scripts to analyse beelzebug json outputs
Beelzebub json logs must be in ./log in gz format
slow contains very slow script without polars (just for me)

## extract to json (output ./json)
source nu main-beel.nu


# display ssh commands 
$dfssh | polars into-nu | explore

# display http commands
$dfhttp | polars into-nu | explore

# display download commands
$download_commands | polars into-nu | explore

# display decoded base 64 commands
$decoded | polars into-nu | explore

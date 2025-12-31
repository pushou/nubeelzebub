# nubeelzebub
NuShell scripts to analyse beelzebug json outputs
You must have polars plugin and xan if you want to graph
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

# split commands in small chunk and graph with xan

$dfssh
        | polars get Command
        | polars select (polars col Command|polars str-split " "|polars explode)
        | polars value-counts
        | polars into-nu
        | str trim --char  "'"
        | sort-by -r  count 
        | first 50
        | to csv --columns [value count]
        | xan hist  -R

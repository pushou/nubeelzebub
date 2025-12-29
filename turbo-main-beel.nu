mut liste_df = ls log/beelzebub.json.*.gz
                  | get name
                  | each {print $in;polars open $in -t ndjson --infer-schema 5000
                         | try { polars get event 
                         | polars unnest event
                         | polars filter ((polars col  Protocol) == 'SSH')
                         | polars select User Password DateTime RemoteAddr Protocol Command SourceIp}}

 
let df_beel = $liste_df |reduce {|it,acc| $it | polars concat $acc }
#$df_beel |polars get Command|polars unique|polars collect|polars into-nu
$df_beel |polars filter (polars col Command|polars contains "uname|wget|export|ftp|curl")|polars get Command|polars unique|polars into-nu

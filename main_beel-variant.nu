use decode_b64.nu *

let filelist = ls log/beelzebub.json.*.gz
                  | get name

let df_ssh = polars open  log/beelzebub.json.*.gz -t ndjson --infer-schema 5000
                         | try { polars get event
                         | polars unnest event
                         | polars filter ((polars col  Protocol) == 'SSH')}

let df_http = polars open  log/beelzebub.json.*.gz -t ndjson --infer-schema 5000
                         | try { polars get event
                         | polars unnest event
                         | polars filter ((polars col  Protocol) == 'HTTP')}

let dfssh = $df_ssh |polars collect
let dfhttp = $df_http |polars collect

let download_commands = $df_ssh |polars filter (polars col Command|polars contains "uname|wget|export|ftp|curl")|polars get Command|polars unique|polars collect

let urls = $dfssh
           | polars get Command
           | polars select (polars col Command|polars str-split " "|polars explode)
           | polars value-counts
           | polars filter ((polars col Command) |polars contains "http://|https://|ftp://|tftp://")
           | polars into-nu
           | sort-by -r count


let decoded = $df_ssh |polars get Command|polars select (polars col Command|polars str-split " "|polars explode)|polars value-counts|polars into-nu
                  | flatten
                  | str trim --char  "'"
                  | decode-b64
                  | tee {save -f ./json/decoded.json} # save base 64 Command and their decoded value
                  | get decoded



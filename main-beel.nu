use decode_b64.nu *

let filelist = ls log/beelzebub.json.*.gz
                  | get name

let df_ssh = $filelist
                  | each {print $in ; polars open $in -t ndjson --infer-schema 5000
                         | try { polars get event
                         | polars unnest event
                         | polars filter ((polars col  Protocol) == 'SSH')
                         | polars select User Password DateTime RemoteAddr Protocol Command SourceIp}}

let df_http = $filelist
                  | each {print $in;polars open $in -t ndjson --infer-schema 5000
                         | try { polars get event 
                         | polars unnest event
                         | polars filter ((polars col  Protocol) == 'HTTP')
                         | polars select DateTime RemoteAddr Protocol  SourceIp Headers Cookies UserAgent  HostHTTPRequest Body HTTPMethod RequestURI TLSServerName
                         }}       

let dfssh = $df_ssh |reduce {|it,acc| $it | polars concat $acc }|polars collect
let dfhttp = $df_http |reduce {|it,acc| $it | polars concat $acc }|polars collect

let download_commands = $dfssh |polars filter (polars col Command|polars contains "uname|wget|export|ftp|curl")|polars get Command|polars unique|polars collect


let decoded = $dfssh |polars get Command|polars select (polars col Command|polars str-split " "|polars explode)|polars value-counts|polars into-nu
                  | flatten
                  | str trim --char  "'"
                  | decode-b64
                  | tee {save -f ./json/decoded.json} # save base 64 Command and their decoded value
                  | get decoded



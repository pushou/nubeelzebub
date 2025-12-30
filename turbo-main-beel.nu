mut df_ssh = ls log/beelzebub.json.*.gz
                  | get name
                  | each {print $in ; polars open $in -t ndjson --infer-schema 5000
                         | try { polars get event 
                         | polars unnest event
                         | polars filter ((polars col  Protocol) == 'SSH')
                         | polars select User Password DateTime RemoteAddr Protocol Command SourceIp}}

mut df_http = ls log/beelzebub.json.*.gz
                  | get name
                  | each {print $in;polars open $in -t ndjson --infer-schema 5000
                         | try { polars get event 
                         | polars unnest event
                         | polars filter ((polars col  Protocol) == 'HTTP')
                         | polars select DateTime RemoteAddr Protocol  SourceIp Headers Cookies UserAgent  HostHTTPRequest Body HTTPMethod RequestURI TLSServerName
                         }}      
 
let dfssh = $df_ssh |reduce {|it,acc| $it | polars concat $acc }
let dfhttp = $df_http |reduce {|it,acc| $it | polars concat $acc }
#$df_beel |polars get Command|polars unique|polars collect|polars into-nu
$dfssh |polars filter (polars col Command|polars contains "uname|wget|export|ftp|curl")|polars get Command|polars unique|polars into-nu

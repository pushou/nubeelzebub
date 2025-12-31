
use ./decode_b64.nu *

zcat  log/beelzebub.json.*.gz
                 | from json --objects
                 | flatten --all
                 | default "nocom" Command
                 | where Command != "nocom" and Command != ""
                 | tee {save -f ./json/beel.json} # save all 
                 | get Command
                 | split words  --min-word-length 3
                 | flatten
                 | str trim --char  "'"
                 | uniq -c
                 | sort-by -r count
                 | tee {save -f ./json/commands.json} # save individual command
                 | decode-b64
                 | tee {save -f ./json/base64.json} # save base 64 Command and their decoded value

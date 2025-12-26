def decode-b64-malware [] {
    $in | each { |row|
        let len = ($row.value | str length)
        let mod = ($len mod 4)
        let padded = (if $mod == 2 { $row.value + "==" } else if $mod == 3 { $row.value + "=" } else { $row.value })

        let decoded = (try {
            $padded | decode base64 | decode iso-8859-1
        } catch {
            null
        })

        if $decoded != null {
          $row | merge {
                value: $row.value
                count: $row.count
                longueur: $len
                decoded: ($decoded | str replace --all --regex '[^[:print:]\n\t]' '.')
            }
        }
    } | where ($it.decoded | str length) > 10
}

zcat  beelzebub.json.*.gz
                 | from json --objects
                 | flatten --all
                 | default "nocom" Command
                 | where Command != "nocom" and Command != ""
                 | get Command
                 | split words  --min-word-length 3
                 | flatten
                 | str trim --char  "'"
                 | uniq -c
                 | sort-by -r count
                 | tee {save -f base64.json}
                 | decode-b64-malware
                 | explore

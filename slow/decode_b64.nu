export def decode-b64 [] {
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

export def turbo-decode-b64 [] {
    $in | each { |row|
        let len = ($row.Command | str length)
        let mod = ($len mod 4)
        let padded = (if $mod == 2 { $row.Command + "==" } else if $mod == 3 { $row.Command + "=" } else { $row.Command })

        let decoded = (try {
            $padded | decode base64 | decode iso-8859-1
        } catch {
            null
        })

        if $decoded != null {
          $row | merge {
                Command: $row.Command
                count: $row.count
                longueur: $len
                decoded: ($decoded | str replace --all --regex '[^[:print:]\n\t]' '.')
            }
        }
    } | where ($it.decoded | str length) > 10
}


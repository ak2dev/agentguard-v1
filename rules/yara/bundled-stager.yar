// AG-SKL-BND-005. Rule-pack data: compiled with includes disabled.
// Download-and-execute commands embedded in a binary or data file. The same
// commands in SKILL.md or scripts are caught by the text rules (AG-SKL-SE-*).

rule ag_bundled_pipe_to_shell
{
    meta:
        agentguard_rule = "AG-SKL-BND-005"
        description = "curl/wget output piped to a shell"
    strings:
        $curl = /curl[ \t][^\n\x00]{1,200}\|[ \t]*(sudo[ \t]+)?(ba|z|da)?sh\b/
        $wget = /wget[ \t][^\n\x00]{1,200}\|[ \t]*(sudo[ \t]+)?(ba|z|da)?sh\b/
    condition:
        any of them
}

rule ag_bundled_powershell_stager
{
    meta:
        agentguard_rule = "AG-SKL-BND-005"
        description = "Encoded PowerShell command or a download cradle"
    strings:
        $enc = /powershell(\.exe)?[ \t][^\n\x00]{0,60}-e(nc|ncodedcommand)?[ \t]+[A-Za-z0-9+\/=]{40,}/ nocase ascii wide
        $dl1 = "DownloadString(" nocase ascii wide
        $dl2 = "DownloadFile(" nocase ascii wide
        $iex1 = "Invoke-Expression" nocase ascii wide
        $iex2 = "IEX(" nocase ascii wide
        $iex3 = "| iex" nocase ascii wide
    condition:
        $enc or (any of ($dl*) and any of ($iex*))
}

rule ag_bundled_quarantine_removal
{
    meta:
        agentguard_rule = "AG-SKL-BND-005"
        description = "Removes the macOS quarantine attribute (skips Gatekeeper)"
    strings:
        $xattr = /xattr[ \t]+(-[a-z]+[ \t]+)*-[a-z]*d[a-z]*[ \t]+com\.apple\.quarantine/
    condition:
        $xattr
}

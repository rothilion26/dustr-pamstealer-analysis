/*
   Dustr / PamStealer variant (2026-10). Tested against the samples described in docs/writeup.md.
*/

import "macho"

rule PamStealer_Dustr_KeychainHelper_kh_tmp
{
    meta:
        description = "Embedded Keychain helper: reads service/account from stdin, calls SecKeychainFindGenericPassword, re-prompts on denial"
        sha256 = "3de269d560df00eef46b96a05af3861b69ec5d881da6722a4d8dc7bafa9c6eef"
        date = "2026-10-17"
    strings:
        $id   = "kh_tmp" ascii
        $api1 = "_SecKeychainFindGenericPassword" ascii
        $api2 = "_SecKeychainItemFreeContent" ascii
        $io   = "___stdinp" ascii
        $nap  = "_nanosleep" ascii
    condition:
        uint32(0) == 0xfeedfacf and filesize < 200KB and
        all of ($api*) and $io and $nap and $id
}

rule PamStealer_Dustr_Stage3_Agent
{
    meta:
        description = "Rust stage-3 agent: hex 'salt:nonce:ct' config literals plus CDP and NSWorkspace launch strings"
        sha256 = "094be93a4fdd3ef075959fb4bd3333f66e31abd1254f66ebaa0ce9460dc7b84a"
        date = "2026-10-17"
    strings:
        $cfg  = /[0-9a-f]{64}:[0-9a-f]{48}:[0-9a-f]{40,}/
        $cdp1 = "\"method\":\"Browser.setDownloadBehavior\"" ascii
        $cdp2 = "\"method\":\"Page.navigate\"" ascii
        $ns1  = "NSWorkspaceOpenConfiguration" ascii
        $ns2  = "setCreatesNewApplicationInstance:" ascii
        $rust = "uncategorized error" ascii
    condition:
        (uint32(0) == 0xbebafeca or uint32(0) == 0xfeedfacf) and
        filesize < 5MB and $cfg and all of ($cdp*) and all of ($ns*) and $rust
}

rule PamStealer_Dustr_Stage3_EmbeddedHelperKey
{
    meta:
        description = "ChaCha20 key and nonce protecting the embedded kh_tmp helper (build-specific)"
        date = "2026-10-17"
    strings:
        $key_nonce = { 81 11 6A 52 48 FC B9 5E 0A 1E F8 85 36 5A 94 6A 72 63 F7 2A 58 4A D0 36 E1 0A CF DA FE AA 47 CF 6A CE B4 58 86 1E 7C 3F FA F4 5C 2F }
    condition:
        $key_nonce
}

rule PamStealer_Dustr_Stage2_Installer_JXA
{
    meta:
        description = "Decrypted stage-2 JXA installer (fake Finder.app builder). Only seen in memory or in analyst output."
        date = "2026-10-17"
    strings:
        $a = "Finder.icns" ascii
        $b = "LSBackgroundOnly" ascii
        $c = "ephemeralSessionConfiguration" ascii
        $d = "may fail to install" ascii
        $e = "applySubscriptionProvider" ascii
    condition:
        filesize < 50KB and 4 of them
}

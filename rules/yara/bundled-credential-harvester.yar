// AG-SKL-BND-004. Rule-pack data: compiled with includes disabled.
// An executable that names several credential stores AND carries an upload
// channel. Either half alone is common in benign tools (browser automation,
// chat integrations); together they are the shape of an information stealer.

rule ag_bundled_credential_harvester
{
    meta:
        agentguard_rule = "AG-SKL-BND-004"
        description = "Executable naming credential stores together with a chat-bot or webhook upload endpoint"

    strings:
        // browser credential and cookie stores
        $store_chrome_login = "Login Data" ascii wide
        $store_chrome_web = "Web Data" ascii wide
        $store_chrome_key = "Local State" ascii wide
        $store_ff_logins = "logins.json" ascii wide
        $store_ff_key = "key4.db" ascii wide
        $store_ff_cookies = "cookies.sqlite" ascii wide
        // crypto wallets (MetaMask's Chrome extension id)
        $store_wallet_dat = "wallet.dat" ascii wide nocase
        $store_metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $store_exodus = "Exodus/exodus.wallet" ascii wide
        $store_electrum = "Electrum/wallets" ascii wide
        // OS keychains, SSH and cloud credentials
        $store_keychain = "login.keychain" ascii wide
        $store_keychain_cli = "find-generic-password" ascii wide
        $store_ssh = ".ssh/id_" ascii wide
        $store_aws = ".aws/credentials" ascii wide
        $store_gcloud = "gcloud/credentials.db" ascii wide
        // upload channels
        $out_telegram = "api.telegram.org/bot" ascii wide
        $out_discord = "discord.com/api/webhooks" ascii wide
        $out_discordapp = "discordapp.com/api/webhooks" ascii wide
        $out_webhook_site = "webhook.site/" ascii wide
        $out_slack = "hooks.slack.com/services" ascii wide

    condition:
        (
            uint32(0) == 0x464c457f                                   // ELF
            or uint16(0) == 0x5a4d                                    // PE (MZ)
            or uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf     // Mach-O
            or uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe
            or uint32(0) == 0xbebafeca                                // fat Mach-O / Java class
            or uint32(0) == 0x6d736100                                // WebAssembly
        )
        and 3 of ($store_*)
        and any of ($out_*)
}

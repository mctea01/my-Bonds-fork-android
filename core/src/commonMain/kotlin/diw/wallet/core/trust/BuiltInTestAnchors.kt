package diw.wallet.core.trust

import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64

/**
 * The issuer and verifier (reader) certificates the Multipaz apps trust out of the box: the Multipaz test app and
 * Multipaz Identity Reader (openwallet-foundation/multipaz samples/testapp App.kt and multipaz-identity-reader backend
 * default_configuration.json, 2026-10-14) and Multipaz Wallet (openwallet-foundation/multipaz-wallet backend
 * default_configuration.json public_data, 2026-10-12): Multipaz, Utopia and Google test IACAs and OpenID4VCI roots,
 * Google Wallet and Apple ID pass issuers, and the Multipaz, Identity Reader, Utopia and David's verifier CAs.
 *
 * Test anchors are stored in the TEST environment, so a match is T3 with the test label and never official. The
 * production ID pass issuers of Google Wallet and Apple ([Anchor.production]) are stored as PRODUCTION anchors that
 * are not official: T3, naming the issuer without placing it on a Taiwanese list.
 */
object BuiltInTestAnchors {
    /** One anchor: its name, the roles it is trusted for, and the certificate. */
    class Anchor(
        val name: String,
        val roles: Set<TrustRole>,
        private val b64: String,
        val production: Boolean = false,
        val source: String = WALLET_SOURCE,
    ) {
        val certificate: X509Cert by lazy { X509Cert(ByteString(b64.fromBase64())) }
    }

    const val SOURCE = "https://github.com/openwallet-foundation/multipaz"
    const val WALLET_SOURCE = "https://github.com/openwallet-foundation/multipaz-wallet"

    private val ISSUER_ROLES = setOf(TrustRole.ISSUER, TrustRole.STATUS_LIST)
    private val VERIFIER_ROLES = setOf(TrustRole.VERIFIER)

    val all: List<Anchor> by lazy {
        listOf(
            Anchor("OWF Multipaz TEST IACA（Multipaz 測試 App 發行端）", ISSUER_ROLES, OWF_TEST_IACA, source = SOURCE),
            Anchor("issuer.multipaz.org（Multipaz OpenID4VCI 發行端）", ISSUER_ROLES, MULTIPAZ_ISSUER_ROOT, source = SOURCE),
            Anchor("verifier.multipaz.org Reader CA（Multipaz 網頁查驗端）", VERIFIER_ROLES, MULTIPAZ_VERIFIER_CA, source = SOURCE),
            Anchor("Multipaz 次要查驗身分（多重簽章請求測試）", VERIFIER_ROLES, SECONDARY_VERIFIER, source = SOURCE),
            Anchor("Multipaz Identity Reader CA", VERIFIER_ROLES, IDENTITY_READER, source = SOURCE),
            Anchor("Multipaz Identity Reader CA（未驗證裝置）", VERIFIER_ROLES, IDENTITY_READER_UNTRUSTED, source = SOURCE),
            Anchor("Utopia Brewery TEST Reader CA", VERIFIER_ROLES, UTOPIA_BREWERY, source = SOURCE),
            Anchor("Utopia Plumbing TEST Reader CA", VERIFIER_ROLES, UTOPIA_PLUMBING, source = SOURCE),
            Anchor("The Utopians Reader CA", VERIFIER_ROLES, UTOPIANS, source = SOURCE),
            Anchor("Google Wallet ID pass（美國）", ISSUER_ROLES, GOOGLE_ID_PASS_US, production = true),
            Anchor("Google Wallet ID pass（美國以外）", ISSUER_ROLES, GOOGLE_ID_PASS_ROW, production = true),
            Anchor("Apple Digital ID（美國）", ISSUER_ROLES, APPLE_DIGITAL_ID_US, production = true),
            Anchor("Multipaz TEST IACA（Multipaz 發行端）", ISSUER_ROLES, MULTIPAZ_TEST_IACA),
            Anchor("utopia.multipaz.org（Utopia 測試發行端）", ISSUER_ROLES, UTOPIA_ISSUER_ROOT),
            Anchor("utopia.multipaz.org（Utopia 測試發行端，2026 更新金鑰）", ISSUER_ROLES, UTOPIA_ISSUER_ROOT_2026),
            Anchor("Google Payground（測試）", ISSUER_ROLES, GOOGLE_PAYGROUND),
            Anchor("Google Wallet ID pass Sandbox（測試）", ISSUER_ROLES, GOOGLE_ID_PASS_SANDBOX),
            Anchor("Multipaz Wallet In-App IACA（Multipaz Wallet 內建發行）", ISSUER_ROLES, MULTIPAZ_WALLET_IACA),
            Anchor("David's Verifier（ws.davidz25.net 測試查驗端）", VERIFIER_ROLES, DAVIDS_VERIFIER),
        )
    }

    /** OWF Multipaz TestApp; Multipaz Identity Reader backend default_configuration.json, test_only. SHA-256 a35d77e06d3673fee8ed93400d4963696e9c7d33f9c3137b3aaf79f21bb7ca92. */
    private const val OWF_TEST_IACA =
        "MIICqDCCAi2gAwIBAgIQNurX5DFyLb9mx2OYJm+AIDAKBggqhkjOPQQDAzAuMR8wHQYDVQQDDBZPV0YgTXVsdGlwYXogVEVTVCBJ" +
        "QUNBMQswCQYDVQQGDAJVUzAeFw0yNDEyMDEwMDAwMDBaFw0zNDEyMDEwMDAwMDBaMC4xHzAdBgNVBAMMFk9XRiBNdWx0aXBheiBU" +
        "RVNUIElBQ0ExCzAJBgNVBAYMAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+wih+L79b" +
        "7jyqUl99sbeUnpxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH5RulaSWThWBfMyRjsfVODkosHLCDnbPVo4IBDjCCAQow" +
        "DgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwTAYDVR0SBEUwQ4ZBaHR0cHM6Ly9naXRodWIuY29tL29wZW53YWxs" +
        "ZXQtZm91bmRhdGlvbi1sYWJzL2lkZW50aXR5LWNyZWRlbnRpYWwwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cHM6Ly9naXRodWIuY29t" +
        "L29wZW53YWxsZXQtZm91bmRhdGlvbi1sYWJzL2lkZW50aXR5LWNyZWRlbnRpYWwvY3JsMB0GA1UdDgQWBBSrZRvgVsKQU/Hdf2zk" +
        "h75o3mDJ9TAfBgNVHSMEGDAWgBSrZRvgVsKQU/Hdf2zkh75o3mDJ9TAKBggqhkjOPQQDAwNpADBmAjEA5f7FMEYm6e4EVsBCGs/6" +
        "QPOLH3W3/sR3nepN/EY+od2U02s8reyVDgyH9i5YBwNFAjEAntYi3uf5M4mLNxIKBqg2Km666ZgWxOLV+Sj/urS8n0WRqF1SapDW" +
        "fa/oeTyF0aJG"

    /** issuer.multipaz.org; Multipaz testapp built-in issuer trust list. SHA-256 77cfe9827a4ec26e7c665ecf4ecc97a5e1e54371e58dd7513d91c393f79ad623. */
    private const val MULTIPAZ_ISSUER_ROOT =
        "MIICvTCCAkKgAwIBAgIQGae+XGbhr63RY7K+8qcoGTAKBggqhkjOPQQDAzBOMT8wPQYDVQQDDDZPcGVuSUQ0VkNJIFJvb3QgYXQg" +
        "aHR0cHM6Ly9pc3N1ZXIubXVsdGlwYXoub3JnL3JlY29yZHMxCzAJBgNVBAYMAlVTMB4XDTI2MDEwNTE2MTkxMVoXDTQxMDEwMTE2" +
        "MTkxMVowTjE/MD0GA1UEAww2T3BlbklENFZDSSBSb290IGF0IGh0dHBzOi8vaXNzdWVyLm11bHRpcGF6Lm9yZy9yZWNvcmRzMQsw" +
        "CQYDVQQGDAJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJdqwFT75XRwnTtjNrLC0Nxr2Sig+3eAJcCqhBpf7+/G8JEmH4Qm3RmJ" +
        "Cs/x7gG3HRK3i4EF6vpuUdjD9W8r9SpTDeB5HEEFwCBVAGjxXpjHjWguQPz0hSNL3kxmLV/TeqOB5DCB4TAOBgNVHQ8BAf8EBAMC" +
        "AQYwEgYDVR0TAQH/BAgwBgEB/wIBADAuBgNVHRIEJzAlhiNodHRwczovL2lzc3Vlci5tdWx0aXBhei5vcmcvcmVjb3JkczBLBgNV" +
        "HR8ERDBCMECgPqA8hjpodHRwczovL2lzc3Vlci5tdWx0aXBhei5vcmcvcmVjb3Jkcy9jcmwvY3JlZGVudGlhbF9zaWduaW5nMB0G" +
        "A1UdDgQWBBQhFDa78rDnSUTQYRLvyQ4q0NDQuzAfBgNVHSMEGDAWgBQhFDa78rDnSUTQYRLvyQ4q0NDQuzAKBggqhkjOPQQDAwNp" +
        "ADBmAjEAx0yXAeGEGk6fILMjGhgWurcO8+SGXNtN+LxjJ44Smvrzso1TRsMuNYrFEM5+TJkUAjEAhr/sIbjOVBifcjZYMyNHitwg" +
        "CJyY+40MstjXu/YcDSz6dBNZ5mAillH9vpjOP2uZ"

    /** Multipaz Verifier (verifier.multipaz.org); Multipaz testapp built-in reader trust list. SHA-256 ef6e27803c00c58309bb49470fd31b0a07aba4942c1b6d7232f778d4bc7ba860. */
    private const val MULTIPAZ_VERIFIER_CA =
        "MIICaTCCAe+gAwIBAgIQtzUvFDCKLUBWQAZ4UnCw5zAKBggqhkjOPQQDAzA3MQswCQYDVQQGDAJVUzEoMCYGA1UEAwwfdmVyaWZp" +
        "ZXIubXVsdGlwYXoub3JnIFJlYWRlciBDQTAeFw0yNTA2MTkyMjE2MzJaFw0zMDA2MTkyMjE2MzJaMDcxCzAJBgNVBAYMAlVTMSgw" +
        "JgYDVQQDDB92ZXJpZmllci5tdWx0aXBhei5vcmcgUmVhZGVyIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEa6oCzC8rfHfwVOmQ" +
        "f83WyHEQFE8HrLK+NxsufJDrSFgMXjhRvPt3fIjlMyRAaf94Y25Ux9tXg+28EzzB/xG7q8P/FQ9nOSJkw4cQJVdD/ufN599uVdfp" +
        "1URdG95Vncuoo4G/MIG8MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMFYGA1UdHwRPME0wS6BJoEeGRWh0dHBz" +
        "Oi8vZ2l0aHViLmNvbS9vcGVud2FsbGV0LWZvdW5kYXRpb24tbGFicy9pZGVudGl0eS1jcmVkZW50aWFsL2NybDAdBgNVHQ4EFgQU" +
        "sYQ5hS9Kbuq/6mKtvFHQgfdIhykwHwYDVR0jBBgwFoAUsYQ5hS9Kbuq/6mKtvFHQgfdIhykwCgYIKoZIzj0EAwMDaAAwZQIwKh87" +
        "sK/cMbzuc9PFvyiSRedr2RoP0fuFK0X8ddOpi6hEMOapHL/Gs/QByROCpDpkAjEA2yLSJDZEu1GI8uChAsDBZwJPtv5KHUjq1Vpo" +
        "k69SNn+zzb1mNpqmiey+tchPBjZm"

    /** Secondary Verifier Identity; Multipaz testapp built-in reader trust list. SHA-256 1243095cca51206cc2eedbe8e18fb770468c393783c4672bf8eaf09eb6696a22. */
    private const val SECONDARY_VERIFIER =
        "MIICDTCCAZOgAwIBAgIQMCloGIxTSblptvBQkKLg7zAKBggqhkjOPQQDAzAZMRcwFQYDVQQDDA5zZWNvbmRhcnkgcm9vdDAeFw0y" +
        "NjA2MjIwMjMzMjVaFw0zMTA2MjIwMjMzMjVaMBkxFzAVBgNVBAMMDnNlY29uZGFyeSByb290MHYwEAYHKoZIzj0CAQYFK4EEACID" +
        "YgAESXo1mV/8EwV2azIIJt12vO4s9QUa5sGr1k0C9Or/0063S92gjzQWRsqs6MgO4DfxA/C4alEPnUZ0Nl0ylWXsVISY1oiWZCIz" +
        "Lz+4Trdt95RtZDis2pTJxvqIDSBmoShbo4GfMIGcMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMDYGA1UdHwQv" +
        "MC0wK6ApoCeGJWh0dHBzOi8vcmVhZGVyLWNhLmV4YW1wbGUuY29tL2NybC5jcmwwHQYDVR0OBBYEFFUcUqsC/ET2XyVpb0NO9e7R" +
        "xDYaMB8GA1UdIwQYMBaAFFUcUqsC/ET2XyVpb0NO9e7RxDYaMAoGCCqGSM49BAMDA2gAMGUCMQClOf4ArIb5uNM353fjt5XMl5Ul" +
        "NlGDoywjc7Suz6E9PHlLsWGtqO3xDHaJGWBcd5UCMHGzTCI4qATnnFUoq6d5yDIewrUpl2NkhGbXqJvXJ9fBF7h0WtDmwDVbFBdo" +
        "rorOhg=="

    /** Multipaz Identity Reader; Multipaz testapp built-in reader trust list, devices in the GREEN boot state. SHA-256 650e9d34e576175353c07bef18b8c21b65cf8e331802fbfc1b035ab11fcd89b0. */
    private const val IDENTITY_READER =
        "MIICYTCCAeegAwIBAgIQOSV5JyesOLKHeDc+0qmtuTAKBggqhkjOPQQDAzAzMQswCQYDVQQGDAJVUzEkMCIGA1UEAwwbTXVsdGlw" +
        "YXogSWRlbnRpdHkgUmVhZGVyIENBMB4XDTI1MDcwNTEyMjAyMVoXDTMwMDcwNTEyMjAyMVowMzELMAkGA1UEBgwCVVMxJDAiBgNV" +
        "BAMMG011bHRpcGF6IElkZW50aXR5IFJlYWRlciBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD4UX5jabDLuRojEp9rsZkAEbP8I" +
        "cuj3qN4wBUYq6UiOkoULMOLUb+78Ygonm+sJRwqyDJ9mxYTjlqliW8PpDfulQZejZo2QGqpB9JPInkrCBol5T+0TUs0ghkE5ZQBs" +
        "VKOBvzCBvDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADBWBgNVHR8ETzBNMEugSaBHhkVodHRwczovL2dpdGh1" +
        "Yi5jb20vb3BlbndhbGxldC1mb3VuZGF0aW9uLWxhYnMvaWRlbnRpdHktY3JlZGVudGlhbC9jcmwwHQYDVR0OBBYEFM+kr4eQcxKW" +
        "Lk16F2RqzBxFcZshMB8GA1UdIwQYMBaAFM+kr4eQcxKWLk16F2RqzBxFcZshMAoGCCqGSM49BAMDA2gAMGUCMQCQ+4+BS8yH20KV" +
        "fSK1TSC/RfRM4M9XNBZ+0n9ePg9ftXUFt5e4lBddK9mL8WznJuoCMFuk8ey4lKnb4nubv5iPIzwuC7C0utqj7Fs+qdmcWNrSYSik" +
        "s2OEnjJiap1cPOPk2g=="

    /** Multipaz Identity Reader (Untrusted Devices); Multipaz testapp built-in reader trust list, other devices. SHA-256 7c1eaa6f6979dbc262a2fbde834fac627e787219575373408da709191ac9d864. */
    private const val IDENTITY_READER_UNTRUSTED =
        "MIICiTCCAg+gAwIBAgIQQd/7PXEzsmI+U14J2cO1bjAKBggqhkjOPQQDAzBHMQswCQYDVQQGDAJVUzE4MDYGA1UEAwwvTXVsdGlw" +
        "YXogSWRlbnRpdHkgUmVhZGVyIENBIChVbnRydXN0ZWQgRGV2aWNlcykwHhcNMjUwNzE5MjMwODE0WhcNMzAwNzE5MjMwODE0WjBH" +
        "MQswCQYDVQQGDAJVUzE4MDYGA1UEAwwvTXVsdGlwYXogSWRlbnRpdHkgUmVhZGVyIENBIChVbnRydXN0ZWQgRGV2aWNlcykwdjAQ" +
        "BgcqhkjOPQIBBgUrgQQAIgNiAATqihOe05W3nIdyVf7yE4mHJiz7tsofcmiNTonwYsPKBbJwRTHa7AME+ToAfNhPMaEZ83lBUTBg" +
        "gsTUNShVp1L5xzPS+jK0tGJkR2ny9+UygPGtUZxEOulGK5I8ZId+35Gjgb8wgbwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI" +
        "MAYBAf8CAQAwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cHM6Ly9naXRodWIuY29tL29wZW53YWxsZXQtZm91bmRhdGlvbi1sYWJzL2lk" +
        "ZW50aXR5LWNyZWRlbnRpYWwvY3JsMB0GA1UdDgQWBBSbz9r9IFmXjiGGnH3Siq90geurxTAfBgNVHSMEGDAWgBSbz9r9IFmXjiGG" +
        "nH3Siq90geurxTAKBggqhkjOPQQDAwNoADBlAjEAomqjfJe2k162S5Way3sEBTcj7+DPvaLJcsloEsj/HaThIsKWqQlQKxgNu1rE" +
        "/XryAjB/Gq6UErgWKlspp+KpzuAAWaKk+bMjcM4aKOKOU3itmB+9jXTQ290Dc8MnWVwQBs4="

    /** Utopia Brewing Company; Multipaz Identity Reader identity from apps.multipaz.org. SHA-256 8f062d99d0e2a85f859859be5fa7b3c183feba9861e2b8c5e50ab02e8ce78d2c. */
    private const val UTOPIA_BREWERY =
        "MIICRTCCAcugAwIBAgIQJGQ57Z/GIpsZ1bBj/H9w+TAKBggqhkjOPQQDAzA1MQswCQYDVQQGDAJVVDEmMCQGA1UEAwwdVXRvcGlh" +
        "IEJyZXdlcnkgVEVTVCBSZWFkZXIgQ0EwHhcNMjUwNzI0MjAzMTUxWhcNMzAwNzI0MjAzMTUxWjA1MQswCQYDVQQGDAJVVDEmMCQG" +
        "A1UEAwwdVXRvcGlhIEJyZXdlcnkgVEVTVCBSZWFkZXIgQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATxQFn8bIEIaMONgvtN3ndB" +
        "NB6piOwHo8XF1vj7Lpd77w+wmdWD60Ia8nHh7z4LmdxbxcgtODb5oDehnW8kR4lR0Pw0V5iUMJRiVb0AsZSOk+WKdfS847NlT0Ip" +
        "5B608WqjgZ8wgZwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cHM6Ly9y" +
        "ZWFkZXItY2EuZXhhbXBsZS5jb20vY3JsLmNybDAdBgNVHQ4EFgQUddH+bvOvKZEFSkMWS8ncN1LvXdswHwYDVR0jBBgwFoAUddH+" +
        "bvOvKZEFSkMWS8ncN1LvXdswCgYIKoZIzj0EAwMDaAAwZQIxAOCgXroeWZOkvMcZHn9hijZesYMTC+3yWZGS39ieBRupLjTalHoy" +
        "6CDZlE/H9CYAbQIwZa+iyQpLzghYOCiXkhRtoe8V8XCP8JwxuQblWQYdNWGohOeLowR3punD3UcJTAPS"

    /** Utopia Plumbing Company; Multipaz Identity Reader identity from apps.multipaz.org. SHA-256 5034ba11a3c4d2d8a146f5472165ae0982144b29ab4425e15d031ff2ff5b37f4. */
    private const val UTOPIA_PLUMBING =
        "MIICRzCCAc2gAwIBAgIQZjjem0ED1YZfrJXIp0QagTAKBggqhkjOPQQDAzA2MQswCQYDVQQGDAJVVDEnMCUGA1UEAwweVXRvcGlh" +
        "IFBsdW1iaW5nIFRFU1QgUmVhZGVyIENBMB4XDTI1MDcyNDIxMjcxMFoXDTMwMDcyNDIxMjcxMFowNjELMAkGA1UEBgwCVVQxJzAl" +
        "BgNVBAMMHlV0b3BpYSBQbHVtYmluZyBURVNUIFJlYWRlciBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABL6vQpn6zrHonK43hm/W" +
        "ED4i3W63IDDA0mtvIzvsBHSGl7YK0Tu7GiqDBNWXtDvxowB8upQv6Us4JVzqI5kzR4D142vmilOb+J9AhOCWxnqmEvqOTSVi/PX9" +
        "r4DrDWVHsqOBnzCBnDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADA2BgNVHR8ELzAtMCugKaAnhiVodHRwczov" +
        "L3JlYWRlci1jYS5leGFtcGxlLmNvbS9jcmwuY3JsMB0GA1UdDgQWBBQMJBLQ4z7QV6bb6Hg/NRlsprAzJTAfBgNVHSMEGDAWgBQM" +
        "JBLQ4z7QV6bb6Hg/NRlsprAzJTAKBggqhkjOPQQDAwNoADBlAjEA4ZdSN9L3fLu2uuLbvctEhFap1myoYongcIlkFaiBnVftzc2U" +
        "8Ziq9fk0bhzwUoYaAjBhZcjyGABTQYv2KH4+Nasqnjnw6PirUmutpPN15G4jzQ63hUp/X7xMfGSQ8Rd7ibU="

    /** The Utopians; Multipaz Identity Reader identity from apps.multipaz.org. SHA-256 60fd37a937641587d42108eeb50ce348a04682114b031fdaf14e18c5705c0717. */
    private const val UTOPIANS =
        "MIIB4DCCAYagAwIBAgIQ6rXL1BAAeNzwRX2GH2BGqjAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZUaGUgVXRvcGlhbnMgUmVhZGVy" +
        "IENBMB4XDTI1MDcyNTE5NDQ1MloXDTMwMDcyNTE5NDQ1MlowITEfMB0GA1UEAwwWVGhlIFV0b3BpYW5zIFJlYWRlciBDQTBZMBMG" +
        "ByqGSM49AgEGCCqGSM49AwEHA0IABLqZ3qQWauWFQo0tbTvhnViU2kBJ4jKPkXxZuFtwlPyF+mYZzygtx5tReifmY9vQXxqi/QVw" +
        "AAsX6sVZK9p42C6jgZ8wgZwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwNgYDVR0fBC8wLTAroCmgJ4YlaHR0" +
        "cHM6Ly9yZWFkZXItY2EuZXhhbXBsZS5jb20vY3JsLmNybDAdBgNVHQ4EFgQUG2vN6fsoBdTeXaUMbiX9MxtpldkwHwYDVR0jBBgw" +
        "FoAUG2vN6fsoBdTeXaUMbiX9MxtpldkwCgYIKoZIzj0EAwIDSAAwRQIgWA7vaJVZgg8CebwCTxDgPu8w/2GvLVAHMa/RprUUSScC" +
        "IQClOLGmxZFQLnKqT7Jy/EHXWM3oJUhyVeehOWauMMJyzQ=="

    /** Google Wallet ID pass (US); Multipaz Wallet trusted issuers. SHA-256 2fa839cf8e08c3579f593ca85d0c0f75a077c4a434c0059dca9fcdf13b9a5b05. */
    private const val GOOGLE_ID_PASS_US =
        "MIIDlzCCAx2gAwIBAgIUAJ85jV+yjp7ZTVXNxpWzt/Bk2OowCgYIKoZIzj0EAwMwWzELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdv" +
        "b2dsZSBMTEMxDzANBgNVBAsTBldhbGxldDEmMCQGA1UEAxMdSWRlbnRpdHkgQ3JlZGVudGlhbCBSb290IElBQ0EwHhcNMjQwNTIy" +
        "MTgxNjUzWhcNMzQwMjIwMDIwNDI4WjBbMQswCQYDVQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIExMQzEPMA0GA1UECxMGV2FsbGV0" +
        "MSYwJAYDVQQDEx1JZGVudGl0eSBDcmVkZW50aWFsIFJvb3QgSUFDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABOLRHBcm+qkIaSDs" +
        "KjEZPkagCC0DwSaVh+eNof9LJD5y1A7D+2Eq1CDfFmUnkqVIubMU3R5En3hjAELlcTw9khXJMiuq9Su1uzqibnrRnFABY230ZNMl" +
        "M0bTlR73kiRou6OCAaAwggGcMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQ7iTqljRX0qKkb" +
        "mPS9B+x+EM6eLDAfBgNVHSMEGDAWgBQ7iTqljRX0qKkbmPS9B+x+EM6eLDCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcwAoZw" +
        "aHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY1Y2ZkZTc3LTAwMDAtMjRkZS05YTIzLTA4OWUwODJiZmZjYy5zdG9yYWdlLmdvb2ds" +
        "ZWFwaXMuY29tLzAyZGI0NjA4MGE2ZDYzZWNhNzYzL2NhLmNydDCBggYDVR0fBHsweTB3oHWgc4ZxaHR0cDovL3ByaXZhdGVjYS1j" +
        "b250ZW50LTY1Y2ZkZTc3LTAwMDAtMjRkZS05YTIzLTA4OWUwODJiZmZjYy5zdG9yYWdlLmdvb2dsZWFwaXMuY29tLzAyZGI0NjA4" +
        "MGE2ZDYzZWNhNzYzL2NybC5jcmwwIQYDVR0SBBowGIYWaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTAKBggqhkjOPQQDAwNoADBlAjEA" +
        "tAjx84AkVDG5VrDIC+7ER67tz1hhHGkUzdGspZVQbWrtS1FB0TDFH/3BuX3U7IPvAjBFgqYCr+g24LZVrUc8y1eQD4gXrGmf7HZf" +
        "IFDUxe6IQHrwB1/UNf1k3FDAMG4pZrg="

    /** Google Wallet ID pass (ROW); Multipaz Wallet trusted issuers. SHA-256 4fa86d55a1da105ee3ab1706a60d2f80841d473773419b309d85df1b407b29e5. */
    private const val GOOGLE_ID_PASS_ROW =
        "MIIDlTCCAxygAwIBAgITZ1Q7u+8TXCBKFn6jmzvPwCx3bDAKBggqhkjOPQQDAzBbMQswCQYDVQQGEwJYRzETMBEGA1UEChMKR29v" +
        "Z2xlIExMQzEPMA0GA1UECxMGV2FsbGV0MSYwJAYDVQQDEx1JZGVudGl0eSBDcmVkZW50aWFsIFJvb3QgSUFDQTAeFw0yNTAzMDQy" +
        "MDUyMThaFw0zNTAzMDUwNjMyMTlaMFsxCzAJBgNVBAYTAlhHMRMwEQYDVQQKEwpHb29nbGUgTExDMQ8wDQYDVQQLEwZXYWxsZXQx" +
        "JjAkBgNVBAMTHUlkZW50aXR5IENyZWRlbnRpYWwgUm9vdCBJQUNBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE10PwkmBoPbxLLzP2" +
        "Uph7NU55nM130T+wp8/QMdPa/SKXzMBTHINFb/uh0LmvKnfgk4wiDhREGM9ty/yuLB/ZT+2abS6cD7FDyvhVBzwNNR0VVsCDdqv2" +
        "Ob8KaQzLAXLno4IBoDCCAZwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBpEaI07wxCy/QSQ" +
        "d9UO5UBlzxTpMB8GA1UdIwQYMBaAFBpEaI07wxCy/QSQd9UO5UBlzxTpMIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBo" +
        "dHRwOi8vcHJpdmF0ZWNhLWNvbnRlbnQtNjdmNWY0MzItMDAwMC0yOTJmLTkxZDYtYWMzZWIxNGU3YjY4LnN0b3JhZ2UuZ29vZ2xl" +
        "YXBpcy5jb20vYWE3NjAzMGUwYjIyYTNhOTVhOGIvY2EuY3J0MIGCBgNVHR8EezB5MHegdaBzhnFodHRwOi8vcHJpdmF0ZWNhLWNv" +
        "bnRlbnQtNjdmNWY0MzItMDAwMC0yOTJmLTkxZDYtYWMzZWIxNGU3YjY4LnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYWE3NjAzMGUw" +
        "YjIyYTNhOTVhOGIvY3JsLmNybDAhBgNVHRIEGjAYhhZodHRwczovL3d3dy5nb29nbGUuY29tMAoGCCqGSM49BAMDA2cAMGQCMEle" +
        "AuFo8yKVGk70NwJ/CzBt08mNHqBsxILZnTHwKvxXRkgDcXbwd931bVvQoTYppQIwTCcq+Kic8KAe1Y2lu0ohvkxwST1s34ytFqJc" +
        "ElPddS76rX4rJLLWwSde7pYC3LmY"

    /** Apple Digital ID (US); Multipaz Wallet trusted issuers. SHA-256 368abe90153936dbcd28b81e21c93b4b5e372898ff73a0c2b707697de252e926. */
    private const val APPLE_DIGITAL_ID_US =
        "MIIC+jCCAoCgAwIBAgIQbwZwl4rwPpc5UqpvfHlLUjAKBggqhkjOPQQDAzBVMQswCQYDVQQGEwJVUzETMBEGA1UECgwKQXBwbGUg" +
        "SW5jLjExMC8GA1UEAwwoQXBwbGUgSXNzdWluZyBBdXRob3JpdHkgRUNDIFJvb3QgQ0EgLSBHMTAeFw0yNTA0MjkyMTQ1MjdaFw00" +
        "MDA0MjUyMTQ1MjZaMFIxCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMS4wLAYDVQQDDCVBcHBsZSBJc3N1aW5nIEF1" +
        "dGhvcml0eSBFQ0MgQ0EgMSAtIEcxMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETZHKqMvi7URBiwFpSHP/QfoyODkSmRgEfy7ihe2u" +
        "YgIhS4bgEyL5tbgy8nidlic59c4jLVj8vYz11upIeeb6LMFw8mG0Pd2tNoNdNDdxoakzobM9Ra9QwSyqKcE5H3nFo4IBFjCCARIw" +
        "EgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBRlD3BF4nVyw2Fnex+hZfLk7G/RpzBABgNVHREEOTA3hjVodHRwczovL3d3" +
        "dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvYXBraTIwMjUwNTAYBgNVHSAEETAPMA0GCyqGSIb3Y2QFFgEBMBsGA1Ud" +
        "JQQUMBIGByiBjF0FAQIGByiBtTQEAQIwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5hcHBsZS5jb20vYWlhZXJjYWcxLmNy" +
        "bDAdBgNVHQ4EFgQUtaXH/AFcuSnQgLECaiofOquMVcQwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQD6ximNM1vd" +
        "v00QCB2/vz5dxEVTLCqinMnLMnlQT2xUFTL7YNE+qK5v6B7ttS/38sQCMDHUpAhT+AhTJKFi8FNMvT06IKp/Lc4FZ8g/Rd3Sp5jd" +
        "e5oGJZQwnBs2NqDRrLndzQ=="

    /** Multipaz Issuer; Multipaz Wallet trusted issuers. SHA-256 075c66af8b60eadd47849692e49e98c340b76be64938e03f3aa93837c305cfc0. */
    private const val MULTIPAZ_TEST_IACA =
        "MIICjDCCAhKgAwIBAgIQrXu/6YI1TLpzNB8/HPjJeDAKBggqhkjOPQQDAzA3MQswCQYDVQQGDAJVUzELMAkGA1UECAwCTUExGzAZ" +
        "BgNVBAMMEk11bHRpcGF6IFRFU1QgSUFDQTAeFw0yNjA2MTUyMDM2MTZaFw0zMTA2MTUyMDM2MTZaMDcxCzAJBgNVBAYMAlVTMQsw" +
        "CQYDVQQIDAJNQTEbMBkGA1UEAwwSTXVsdGlwYXogVEVTVCBJQUNBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETxD43A6lF+6kjkmx" +
        "KfgUWcMCthcan9RiolJXyxpZ91JLWfIdctq7DGLEdDbA4p1Xu5/fdI8hV8XD6wlzol5ojAOZuutF8hrt8IAtYK0+nFHlQ/g7avvW" +
        "NmezWUJWJZm7o4HiMIHfMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMC0GA1UdEgQmMCSGImh0dHBzOi8vaXNz" +
        "dWVyLmV4YW1wbGUuY29tL3dlYnNpdGUwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cHM6Ly9naXRodWIuY29tL29wZW53YWxsZXQtZm91" +
        "bmRhdGlvbi9tdWx0aXBhei9jcmwuY3JsMB0GA1UdDgQWBBT3+GB/kV1+37tVu4jRNalcBVujDjAfBgNVHSMEGDAWgBT3+GB/kV1+" +
        "37tVu4jRNalcBVujDjAKBggqhkjOPQQDAwNoADBlAjA4xjEeGHV0DaUrlbCb2rPTjjwJ2IS5YQu94xDbKkLVIcBQ4DmppcfpZST6" +
        "lAPTw5wCMQDtjAA9CzRo1db1jC4eMMcCgX4DXf5u3007djJFXg4r6K27gsFIVHMWoBB0qw/isLQ="

    /** utopia.multipaz.org; Multipaz Wallet trusted issuers. SHA-256 5877024777fbdc7fe9958b8480869370972e32cbee15c0612442e53856629598. */
    private const val UTOPIA_ISSUER_ROOT =
        "MIICwDCCAkagAwIBAgIQx0DYC16CUdQPWBoF0eNcoTAKBggqhkjOPQQDAzBPMUAwPgYDVQQDDDdPcGVuSUQ0VkNJIFJvb3QgYXQg" +
        "aHR0cHM6Ly91dG9waWEubXVsdGlwYXoub3JnL3JlZ2lzdHJ5MQswCQYDVQQGDAJVUzAeFw0yNjA2MTgxOTQ5MzBaFw00MTA2MTQx" +
        "OTQ5MzBaME8xQDA+BgNVBAMMN09wZW5JRDRWQ0kgUm9vdCBhdCBodHRwczovL3V0b3BpYS5tdWx0aXBhei5vcmcvcmVnaXN0cnkx" +
        "CzAJBgNVBAYMAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXWSGu5LdRhSdtvbVhOgO3XBsjS8qclm4S6p6rOeDbGBVigQhvO3g" +
        "8BPdr7n8hdvsDdfc9Ooh/0tz8+2bNwrR9V4DhfEneqChWLtQ/fRwTibvmBjSTezCf4/s+i+ZtHYHo4HmMIHjMA4GA1UdDwEB/wQE" +
        "AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMC8GA1UdEgQoMCaGJGh0dHBzOi8vdXRvcGlhLm11bHRpcGF6Lm9yZy9yZWdpc3RyeTBM" +
        "BgNVHR8ERTBDMEGgP6A9hjtodHRwczovL3V0b3BpYS5tdWx0aXBhei5vcmcvcmVnaXN0cnkvY3JsL2NyZWRlbnRpYWxfc2lnbmlu" +
        "ZzAdBgNVHQ4EFgQUIC0jIgjKmykwZZLeJyAU/eQtzPcwHwYDVR0jBBgwFoAUIC0jIgjKmykwZZLeJyAU/eQtzPcwCgYIKoZIzj0E" +
        "AwMDaAAwZQIxAJSaluaAlfdeeC01gmBdkqMlAM8+bNvenByPBOY7V9kJmv8GgaHHtMxRcBjjr+P9XwIwP96fOexFJr3EFnifcw8i" +
        "7WFUQTDyMRUPGp3uK10Um5jpXDZeaC95CsDxQhc4S6qR"

    /**
     * utopia.multipaz.org registry root, rotated 2026-09-30 (served by /id/signing_certificate). The server re-keyed its
     * "OpenID4VCI Root at https://utopia.multipaz.org/registry" root, so credentials issued after the rotation chain to
     * this key, not [UTOPIA_ISSUER_ROOT]; both are kept so test cards from before and after the rotation stay trusted.
     * SHA-256 7f0ba1aae4a4c5c6fec04b9de59366d96bb2eb352877dbfdafa962e2a7deeb35.
     */
    private const val UTOPIA_ISSUER_ROOT_2026 =
        "MIICwTCCAkegAwIBAgIRANjjMbhVeqt94GRq8Xm0JYEwCgYIKoZIzj0EAwMwTzFAMD4GA1UEAww3T3BlbklENFZDSSBS" +
        "b290IGF0IGh0dHBzOi8vdXRvcGlhLm11bHRpcGF6Lm9yZy9yZWdpc3RyeTELMAkGA1UEBgwCVVMwHhcNMjYwOTMwMjAw" +
        "MDIzWhcNNDEwOTI2MjAwMDIzWjBPMUAwPgYDVQQDDDdPcGVuSUQ0VkNJIFJvb3QgYXQgaHR0cHM6Ly91dG9waWEubXVs" +
        "dGlwYXoub3JnL3JlZ2lzdHJ5MQswCQYDVQQGDAJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABAndoFbMdBfqjQ61Cjkx" +
        "AOE14gRQT/ruL+cfzZYEdRSyu1aLMjP7TFaWzLh96uqE/JFMIfvQk5uJ655+s8IE1UGM8CBhbz0b2lVhy8ts9QleaCNf" +
        "YSu/FdW30P2vdrPyK6OB5jCB4zAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAvBgNVHRIEKDAmhiRo" +
        "dHRwczovL3V0b3BpYS5tdWx0aXBhei5vcmcvcmVnaXN0cnkwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cHM6Ly91dG9waWEu" +
        "bXVsdGlwYXoub3JnL3JlZ2lzdHJ5L2NybC9jcmVkZW50aWFsX3NpZ25pbmcwHQYDVR0OBBYEFHmysRh2V3vETnd4PvQ4" +
        "PfE8J8LJMB8GA1UdIwQYMBaAFHmysRh2V3vETnd4PvQ4PfE8J8LJMAoGCCqGSM49BAMDA2gAMGUCMAsUsdV/DyYe74+s" +
        "bXe1vey6v80WfRwb4St4FMvpc0/46+qdVQt7ZYuJZns5uRZf0QIxAPEXP72RZCzGPuPkAUc9eXiZOjGLIjyRbkyJ24x4" +
        "U0qz4f+EW8HqMiAPjf0pF7wcCw=="

    /** Google Payground; Multipaz Wallet trusted issuers. SHA-256 847f9abf31f7a22de23b21b849a5ab6fbbe0826c030469e55d71ef2e79b27296. */
    private const val GOOGLE_PAYGROUND =
        "MIIC/jCCAmCgAwIBAgIJAI2FjRUdyT0BMAoGCCqGSM49BAMEMDcxCzAJBgNVBAYTAlpaMQ8wDQYDVQQKDAZHb29nbGUxFzAVBgNV" +
        "BAMMDlBheWdyb3VuZCBSb290MB4XDTI1MDQyODA0MDcxMFoXDTM1MDQyNjA0MDcxMFowNzELMAkGA1UEBhMCWloxDzANBgNVBAoM" +
        "Bkdvb2dsZTEXMBUGA1UEAwwOUGF5Z3JvdW5kIFJvb3QwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAEjCus99ox1/datgRORqDvJ" +
        "q34+Xm1keediDUXacFW+RzMFOu4sK1yDDliqWtXThHi8jTUVsoYohzxCmPbOumFTvAArCpNF5BoYFRtDTcMEKZ0ZZ5NM8OLDO+FM" +
        "rWZq6GJoDbA+HkDkgdIX3/Xrh52CZRc1ulOlWjzwtu1eSFLfXfVlY6OCARAwggEMMB0GA1UdDgQWBBRzpwQeUIGTnuDbtwKK43Ev" +
        "0Ko2wTAfBgNVHSMEGDAWgBRzpwQeUIGTnuDbtwKK43Ev0Ko2wTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAh" +
        "BgNVHRIEGjAYhhZodHRwczovL3d3dy5nb29nbGUuY29tMIGCBgNVHR8EezB5MHegdaBzhnFodHRwOi8vcHJpdmF0ZWNhLWNvbnRl" +
        "bnQtNjYwM2M2NDctMDAwMC0yOWQ0LWFlYTYtZjRmNWU4MGQxYjkwLnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vNDFkNDM2ODU5ZTQ1" +
        "ZGJmM2U1YTkvY3JsLmNybDAKBggqhkjOPQQDBAOBiwAwgYcCQgH+co3yU5I2KQyAP8Rf85onNd65dzjBna6nvd7HAMFxcPSG7xMu" +
        "+drc8uVSmi0SYAw4M0fo0YTxphg/xDuc5ekGTQJBcqy8C/+CBBVt4YsJWLgV5rSqIf7u7i69b2s2NHL8nypSqTn9pQRlQjs7qLgZ" +
        "yM1LjKbCPaCU8OrsLiNoCOxMXvc="

    /** Google Wallet ID pass Sandbox; Multipaz Wallet trusted issuers. SHA-256 72a42be2c9acaeca90671d1ac29bc0759f3189d1930b826e3dd9f4ac33693d71. */
    private const val GOOGLE_ID_PASS_SANDBOX =
        "MIIDmzCCAyCgAwIBAgITGdeIKSF7+Y/ntpk9gS5ePWql5TAKBggqhkjOPQQDAzBdMQswCQYDVQQGEwJaWjETMBEGA1UEChMKR29v" +
        "Z2xlIExMQzEPMA0GA1UECxMGV2FsbGV0MSgwJgYDVQQDEx9URVNUIFVTRSBPTkxZIEdJQ0kgU3RhZ2luZyBSb290MB4XDTI1MDQw" +
        "MzE5MTYyNVoXDTM1MDQwNDA1MTM1MFowXTELMAkGA1UEBhMCWloxEzARBgNVBAoTCkdvb2dsZSBMTEMxDzANBgNVBAsTBldhbGxl" +
        "dDEoMCYGA1UEAxMfVEVTVCBVU0UgT05MWSBHSUNJIFN0YWdpbmcgUm9vdDB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSqOrH0F1NP" +
        "SZ5bF7rY4Z0YJi29nQwBPEjrCB6LnMuoZKZgcfb4PiCCVML7PtJlyO4CJBjJeymvXPjayoHLJ5voaU5lpMe2KCzpr+2BTjYPXrzl" +
        "OSeckFneDekg1ayxHqOCAaAwggGcMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSUgUSodq2a" +
        "lxksRsxFAPNdbCAdGDAfBgNVHSMEGDAWgBSUgUSodq2alxksRsxFAPNdbCAdGDCBjQYIKwYBBQUHAQEEgYAwfjB8BggrBgEFBQcw" +
        "AoZwaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTY4MDUxMDlhLTAwMDAtMjNkYS04NGI0LWQ0ZjU0N2VjNmQ2MC5zdG9yYWdlLmdv" +
        "b2dsZWFwaXMuY29tLzczNzYwMDQzMjk2YzFiNjdjMGM2L2NhLmNydDCBggYDVR0fBHsweTB3oHWgc4ZxaHR0cDovL3ByaXZhdGVj" +
        "YS1jb250ZW50LTY4MDUxMDlhLTAwMDAtMjNkYS04NGI0LWQ0ZjU0N2VjNmQ2MC5zdG9yYWdlLmdvb2dsZWFwaXMuY29tLzczNzYw" +
        "MDQzMjk2YzFiNjdjMGM2L2NybC5jcmwwIQYDVR0SBBowGIYWaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTAKBggqhkjOPQQDAwNpADBm" +
        "AjEA81XENiTI3CuvJL7K3uEOhCL+F8io19Arg7D0XvcZUElsc3dMJc1uiUEn6s8IBRPyAjEA9eF3Bzvgh8sVA33ApGKUr0K9KECw" +
        "mR2flxGVZd9ne94hvYAyEDaqs+vE3eIAjtJD"

    /** Multipaz Wallet In-App IACA; Multipaz Wallet trusted issuers. SHA-256 039b7a04f5309d8c8b1a4e83fa9d9814948e1765163412b458e1c63ede2b33af. */
    private const val MULTIPAZ_WALLET_IACA =
        "MIICcDCCAhagAwIBAgIRAJWn0Akgz0sEZ1WuGOnkn0UwCgYIKoZIzj0EAwIwUzELMAkGA1UEBgwCVVMxCzAJBgNVBAgMAk1BMREw" +
        "DwYDVQQKDAhNdWx0aXBhejEkMCIGA1UEAwwbTXVsdGlwYXogV2FsbGV0IEluLUFwcCBJQUNBMB4XDTI2MDkxNjIwNTAxNFoXDTI5" +
        "MTIyOTIwNTAxNFowUzELMAkGA1UEBgwCVVMxCzAJBgNVBAgMAk1BMREwDwYDVQQKDAhNdWx0aXBhejEkMCIGA1UEAwwbTXVsdGlw" +
        "YXogV2FsbGV0IEluLUFwcCBJQUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfr/M6FefKFmcgoTBqKeiuO0qw5IOjP+9g5eZ" +
        "oSzSCZuyftOQb0yCQGErW0PTCrgOWEmPWGKETaC5Gzmr3SxbAaOByjCBxzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB" +
        "/wIBADArBgNVHRIEJDAihiBodHRwczovL2Rldi53YWxsZXQubXVsdGlwYXoub3JnLzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwczov" +
        "L2Rldi53YWxsZXQubXVsdGlwYXoub3JnL2NybDAdBgNVHQ4EFgQUqnhVfyeCgE3Gh+mAXemY3i+hAkEwHwYDVR0jBBgwFoAUqnhV" +
        "fyeCgE3Gh+mAXemY3i+hAkEwCgYIKoZIzj0EAwIDSAAwRQIgS/t+icKw8kUCtlwgFx2pGccSnjLEkMICsFz185yRotICIQDfIw+H" +
        "J/CXq/INi1NlGXKYo0xY2f7bxAJJBFNfM4fFyA=="

    /** David's Verifier; Multipaz Wallet trusted readers. SHA-256 b65c96e14850ab4c1eb0d49a162adb8caa935b15a3a6f572f7a5738e5bbc5b43. */
    private const val DAVIDS_VERIFIER =
        "MIICfjCCAgSgAwIBAgIQJcmMK89tPNDdH7WpEBuqQDAKBggqhkjOPQQDAzBAMTEwLwYDVQQDDChWZXJpZmllciBSb290IGF0IGh0" +
        "dHBzOi8vd3MuZGF2aWR6MjUubmV0MQswCQYDVQQGDAJVUzAeFw0yNjAxMjgxMzExMDhaFw00MTAxMjQxMzExMDhaMEAxMTAvBgNV" +
        "BAMMKFZlcmlmaWVyIFJvb3QgYXQgaHR0cHM6Ly93cy5kYXZpZHoyNS5uZXQxCzAJBgNVBAYMAlVTMHYwEAYHKoZIzj0CAQYFK4EE" +
        "ACIDYgAEuSk/1XRVNYel5yV3RgxtUNlUE85dLTjyKItqz1RUNyOZ7ZHzH4oadb6WnCcLbl5Px+f6i8ytcyh4diTQWG2gtuSRxo05" +
        "PfeZR2rBy0ToZvoVgI9j8nDbfyRGEMrSTHf4o4HCMIG/MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMCIGA1Ud" +
        "EgQbMBmGF2h0dHBzOi8vd3MuZGF2aWR6MjUubmV0MDUGA1UdHwQuMCwwKqAooCaGJGh0dHBzOi8vd3MuZGF2aWR6MjUubmV0L2Ny" +
        "bC92ZXJpZmllcjAdBgNVHQ4EFgQU1TlDuv6QRGOCxyVsiV4KfUT0yvMwHwYDVR0jBBgwFoAU1TlDuv6QRGOCxyVsiV4KfUT0yvMw" +
        "CgYIKoZIzj0EAwMDaAAwZQIwUSENplERttXfOr7yHxbdIhcHdlVEaXLUDbPyXcXW1hbL168wE0ykh6v0grJcD/P1AjEA23KTndS1" +
        "cXfSi5jLDyB+OZY6O5EpVhxjxwZDwucfo2L1zPTt/emPh8XuL625gPbY"
}

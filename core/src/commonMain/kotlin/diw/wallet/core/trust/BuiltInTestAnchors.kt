package diw.wallet.core.trust

import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64

/**
 * The issuer and verifier (reader) certificates the Multipaz test app and Multipaz Identity Reader trust out of the
 * box (openwallet-foundation/multipaz samples/testapp App.kt and multipaz-identity-reader backend
 * default_configuration.json, 2026-10-14): the OWF Multipaz TEST IACA and the issuer.multipaz.org OpenID4VCI root
 * for issuers, and the verifier.multipaz.org, Identity Reader and Utopia reader CAs for verifiers.
 *
 * They are test anchors: the wallet stores them in the TEST environment, so a match is T3 with the test label and is
 * never shown as official.
 */
object BuiltInTestAnchors {
    /** One anchor: its name, the roles it is trusted for, and the certificate. */
    class Anchor(val name: String, val roles: Set<TrustRole>, private val b64: String) {
        val certificate: X509Cert by lazy { X509Cert(ByteString(b64.fromBase64())) }
    }

    const val SOURCE = "https://github.com/openwallet-foundation/multipaz"

    private val ISSUER_ROLES = setOf(TrustRole.ISSUER, TrustRole.STATUS_LIST)
    private val VERIFIER_ROLES = setOf(TrustRole.VERIFIER)

    val all: List<Anchor> by lazy {
        listOf(
            Anchor("OWF Multipaz TEST IACA（Multipaz 測試 App 發行端）", ISSUER_ROLES, OWF_TEST_IACA),
            Anchor("issuer.multipaz.org（Multipaz OpenID4VCI 發行端）", ISSUER_ROLES, MULTIPAZ_ISSUER_ROOT),
            Anchor("verifier.multipaz.org Reader CA（Multipaz 網頁查驗端）", VERIFIER_ROLES, MULTIPAZ_VERIFIER_CA),
            Anchor("Multipaz 次要查驗身分（多重簽章請求測試）", VERIFIER_ROLES, SECONDARY_VERIFIER),
            Anchor("Multipaz Identity Reader CA", VERIFIER_ROLES, IDENTITY_READER),
            Anchor("Multipaz Identity Reader CA（未驗證裝置）", VERIFIER_ROLES, IDENTITY_READER_UNTRUSTED),
            Anchor("Utopia Brewery TEST Reader CA", VERIFIER_ROLES, UTOPIA_BREWERY),
            Anchor("Utopia Plumbing TEST Reader CA", VERIFIER_ROLES, UTOPIA_PLUMBING),
            Anchor("The Utopians Reader CA", VERIFIER_ROLES, UTOPIANS),
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
}

package diw.wallet.core.trust

import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64

/**
 * Public CA roots built into the wallet, generated on 2026-10-11 and checked against their sources:
 * - mainland China CAs: the roots of CFCA, GDCA, SHECA, BJCA, iTrusChina and TrustAsia in the Mozilla or Microsoft
 *   root programs (CCADB, SHA-256 checked), and SM2 roots (Chinese national algorithms) of licensed CAs, downloaded
 *   from each CA's own site and checked against the fingerprints it publishes;
 * - common services: the roots at the top of the certificate chains that the e-invoice and immigration services use
 *   (China's tax administration and immigration administration, Taiwan's e-invoice platform and immigration agency),
 *   as served by those sites on 2026-10-11.
 *
 * A chain to any of them is T3, like the platform store: a public CA verified a domain or organisation. The mainland
 * China group is switched on and off on its own.
 */
object BuiltInPublicRoots {
    enum class Group { MAINLAND_CHINA, SERVICE }

    class Root(
        val name: String,
        val owner: String,
        val group: Group,
        /** Key algorithm and size, e.g. "RSA 4096", "ECC secp384r1", "SM2". */
        val algorithm: String,
        /** What the CA issues for, and the services known to use it. */
        val purposes: String,
        val source: String,
        val sha256: String,
        private val b64: String,
    ) {
        val certificate: X509Cert by lazy { X509Cert(ByteString(b64.fromBase64())) }
        val national: Boolean get() = algorithm == "SM2"
    }

    /** The date the set of roots last changed (UTC). */
    const val UPDATED = "2026-10-11"

    const val MAINLAND_SOURCE = "builtin:mainland-china"
    const val SERVICE_SOURCE = "builtin:services"

    val all: List<Root> by lazy {
        listOf(
        Root(
            name = "CFCA EV ROOT",
            owner = "中國金融認證中心 CFCA",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站與服務；國家稅務總局發票查驗平台、數電票平台與國家移民管理局的網站憑證都簽發自此根憑證",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "5CC3D78E4E1D5E45547A04E6873E64F90CF9536D1CCC2EF800F355C4C5FD70FD",
            b64 = "MIIFjTCCA3WgAwIBAgIEGErM1jANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFs" +
            "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYDVQQDDAxDRkNBIEVWIFJPT1QwHhcNMTIwODA4MDMwNzAxWhcNMjkxMjMxMDMw" +
            "NzAxWjBWMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYD" +
            "VQQDDAxDRkNBIEVWIFJPT1QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDXXWvNED8fBVnVBU03sQ7smCuOFR36k0sX" +
            "giFxEFLXUWRwFsJVaU2OFW2fvwwbwuCjZ9YMrM8irq93VCpLTIpTUnrD7i7es3ElweldPe6hL6P3KjzJIx1qqx2hp/Hz7KDVRM8V" +
            "z3IvHWOX6Jn5/ZOkVIBMUtRSqy5J35DNuF++P96hyk0g1CXohClTt7GIH//62pCfCqktQT+x8Rgp7hZZLDRJGqgG16iI0gNyejLi" +
            "6mhNbiyWZXvKWfry4t3uMCz7zEasxGPrb382KzRzEpR/38wmnvFyXVBlWY9ps4deMm/DGIq1lY+wejfeWkU7xzbh72fROdOXW3Ni" +
            "GUgthxwG+3SYIElz8AXSG7Ggo7cbcNOIabla1jj0Ytwli3i/+Oh+uFzJlU9fpy25IGvPa931DfSCt/SyZi4QKPaXWnuWFo8BGS1s" +
            "bn85WAZkgwGDg8NNkt0yxoekN+kWzqotaK8KgWU6cMGbrU1tVMoqLUuFG7OA5nBFDWteNfB/O7ic5ARwiRIlk9oKmSJgamNgTnYG" +
            "mE69g60dWIolhdLHZR4tjsbftsbhf4oEIRUpdPA+nJCdDC7xij5aqgwJHsfVPKPtl8MeNPo4+QgO48BdK4PRVmrJtqhUUy54Mmc9" +
            "gn900PvhtgVguXDbjgv5E1hvcWAQUhC5wUEJ73IfZzF4/5YFjQIDAQABo2MwYTAfBgNVHSMEGDAWgBTj/i39KNALtbq2osS/BqoF" +
            "jJP7LzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU4/4t/SjQC7W6tqLEvwaqBYyT+y8wDQYJKoZI" +
            "hvcNAQELBQADggIBACXGumvrh8vegjmWPfBEp2uEcwPenStPuiB/vHiyz5ewG5zz13ku9Ui20vsXiObTej/tUxPQ4i9qecsAIyjm" +
            "HjdXNYmEwnZPNDatZ8POQQaIxffu2Bq41gt/UP+TqhdLjOztUmCypAbqTuv0axn96/Ua4CUqmtzHQTb3yHQFhDmVOdYLO6Qn+gjY" +
            "XB74BGBSESgoA//vU2YApUo0FmZ8/Qmkrp5nGm9BC2sGE5uPhnEFtC+NiWYzKXZUmhH4J/qyP5Hgzg0b8zAarb8iXRvTvyUFTeGS" +
            "Gn+ZnzxEk8rUQElsgIfXBDrDMlI1Dlb4pd19xIsNER9Tyx6yF7Zod1rg1MvIB671Oi6ON7fQAUtDKXeMOZePglr4UeWJoBjnaH9d" +
            "Ci77o0cOPaYjesYBx4/IXr9tgFa+iiS6M+qf4TIRnvHST4D2G0CvOJ4RUHlzEhLN5mydLIhyPDCBBpEi6lmt2hkuIsKNuYyH4Ga8" +
            "cyNfIWRjgEj1oDwYPZTISEEdQLpe/v5WOaHIz16eGWRGENoXkbcFgKyLmZJ956LYBws2J+dIeWCKw9cTXPhyQN9Ky8+ZAAoACxGV" +
            "2lZFA4gKn2fQ1XmxqI1AbQ3CekD6819kR5LLU7m7Wc5P/dAVUwHY3+vZ5nbv0CO7O6l5s9UCKc2Jo5YPSjXnTkLAdc0Hz+Ys63su",
        ),
        Root(
            name = "CFCA Identity CA",
            owner = "中國金融認證中心 CFCA",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "身分與文件簽章",
            source = "CCADB（Microsoft 根憑證計畫）",
            sha256 = "FFB85C26308A961351249EA641F659D49F639E91DAED9C92D046CCDCECC93D2F",
            b64 = "MIIFoTCCA4mgAwIBAgIQLHA+VOkP2ZggzMbZ9UY/NTANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hp" +
            "bmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRkwFwYDVQQDDBBDRkNBIElkZW50aXR5IENBMB4XDTE1MDYzMDAx" +
            "MjExMloXDTQwMDYzMDAxMjExMlowWjELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9u" +
            "IEF1dGhvcml0eTEZMBcGA1UEAwwQQ0ZDQSBJZGVudGl0eSBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOFRJSx4" +
            "u/rui1XDTiVkGS2UQqTm3oQPITUo3DKJPvs0c3tX6awSKUoMmCzOyb+kT6VtDs7CzhgJMRBwcg0ia5798whuktLAJc+1s+thfxeE" +
            "/HVrtaxXF0EZDDTVL1Fu1fdRa3FvMrHi066g1jsUUEgZdPztr7UgqJLgP64H0VC81d2v1tD5zs6SuMaBjMX5OY2+9hsumjhkv7fN" +
            "cuf/7YlauKR1WuH+rzIMbSJukzWoYuLArgqX0bCqPvY6UB6bUCoH25eVYAM/o6RdGVUhJzpJnsvI7CzMmxdI0wgQsqlvIQH0WmHd" +
            "096JXbUK8+AV1wZ3C17YaFjfoHe+XxQKRL0tHxo+8aosXQyFDOej24s4BqVbd0zUyt1XleSj6LJkd9k0r2gdKm0/MkcmmTOfCmBo" +
            "EVZb1gLxhyrYadhRKZej3vchJozd8yyMBY+ZNkqQsVhpOf2U0xfWpinDUAvVu6MhQE+xBxwAZFfjUVRz4+sZdAKIdw/RflWDAszZ" +
            "zHSlAWyvlbC52RindZoeTo9rXkNHKjGEA6yIETDos7F4x0PhrQWHnGhLI597ND/M/e+cQsvxNhELNdqaeqGvhU4uWmwneQtFgSV2" +
            "ZG9k52jKluUEMQVYnqi0j/h9VsTtKDHNbYnikHh78ZAalERJ04PvGCPHamW+n+q0e7VjBONc4Xf7AgMBAAGjYzBhMB8GA1UdIwQY" +
            "MBaAFMCsdqLTXf/2zRYAWzinf1V9hVlsMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTArHai013/" +
            "9s0WAFs4p39VfYVZbDANBgkqhkiG9w0BAQsFAAOCAgEAfNPmbXRLuY9du1uVIvxlr0psXoETrLoUCE2v8Hnx0iVCwPjZZCoCNcHh" +
            "Kg86fWoaOhZhG0FGqHVDv9881e1MO0O8LJA5/kyOeetQvsDNWFihMB46a5GR4TRxlSEUoCASy4MqzIGuRuAebbIMytOCiPpua3i2" +
            "XK28QSvafkMLgjP9MqwF/KmKfE5YrTcWCfRgdMVT3JNtZYC9cSCF8RCFOGQj0yGCgeu3bSZlTqvQ1hB1huroHTWf6HdWsZO6qfl3" +
            "BdQeIg1LuIflM58K4QG8kSQurL+hAzASN06V3rziYz6cM+bYWP5twY+2cwrBGkrB4IsqxzdCZfbFyHXe+UxlqDb/2+ldPczGY/A2" +
            "C3sCT89pvcLvpZ4hTl616jBEo4MtMYYJJKRWwYTz63w2czJtF6HnpTCT01q6h2aMBmjJbhNI75kpUd3FBDdj3lY7jKX3XIVAHPDU" +
            "LuM43ojnpoiKkmo7gSehjl/9LIJYlq/asEdwPg4kUwymUeqCo8ttc66xcAeNM4A2P6ywPl8eBrtuVfYZK+xq/ZuaMnqRortgZGH5" +
            "7BRmxsE3vrrcsNSvGhpdd66EVqGxzGO8kzfDRDi0hDFjuKX4wrGIoNnmRdlHESm7na7pbEGyTl2VwHLlAnbv0NtBPu/gL/ukgvx6" +
            "0RunN4pJo8d/DG9CNhx9gMl9JH4=",
        ),
        Root(
            name = "GDCA TrustAUTH R5 ROOT",
            owner = "數安時代 GDCA",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站與文件簽章；電子發票的電子文件驗簽頒發者憑證",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "BFFF8FD04433487D6A8AA60C1A29767A9FC2BBB05E420F713A13B992891D3893",
            b64 = "MIIFiDCCA3CgAwIBAgIIfQmX/vBH6nowDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCQ04xMjAwBgNVBAoMKUdVQU5HIERPTkcg" +
            "Q0VSVElGSUNBVEUgQVVUSE9SSVRZIENPLixMVEQuMR8wHQYDVQQDDBZHRENBIFRydXN0QVVUSCBSNSBST09UMB4XDTE0MTEyNjA1" +
            "MTMxNVoXDTQwMTIzMTE1NTk1OVowYjELMAkGA1UEBhMCQ04xMjAwBgNVBAoMKUdVQU5HIERPTkcgQ0VSVElGSUNBVEUgQVVUSE9S" +
            "SVRZIENPLixMVEQuMR8wHQYDVQQDDBZHRENBIFRydXN0QVVUSCBSNSBST09UMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC" +
            "AgEA2aMW8Mh0dHeb7zMNOwZ+Vfy1YI92hhJCfVZmPoiC7XJjDp6L3TQsAlFRwxn9WVSEyfFrs0yw6ehGXTjGoqcuEVe6ghWinI9t" +
            "sJlKCvLriXBjTnnEt1u9ol2x8kECK62pOqPseQrsXzrj/e+APK00mxqriCZ7VqKChh/rNYmDf1+uKU49tm7srsHwJ5uu4/Ts765/" +
            "94Y9cnrrpftZTqfrlYwiOXnhLQiPzLyRuEH3FMEjqcOtmkVEs7LXLM3GKeJQEK5cy4KOFxg2fZfmiJqwTTQJ9Cy5WmYqsBebnh52" +
            "nUpmMUHfP/vFBu8btn4aRjb3ZGM74zkYI+dndRTVdVeSN72+ahsmUPI2JgaQxXABZG12ZuGR224HwGGALrIuL4xwp9E7PLOR5G62" +
            "xDtw8mySlwnNR30YwPO7ng/Wi64HtloPzgsMR6flPri9fcebNaBhlzpBdRfMK5Z3KpIhHtmVdiBnaM8Nvd/WHwlqmuLMc3GkL30S" +
            "gLdTMEZeS1SZD2fJpcjyIMGC7J0R38IC+xo70e0gmu9lZJIQDSri3nDxGGeCjGHeuLzRL5z7D9Ar7Rt2ueQ5Vfj4oR24qoAATILn" +
            "sn8JuLwwoC8N9VKejveSswoAHQBUlwbgsQfZxw9cZX08bVlX5O2ljelAU58VS6Bx9hoh49pwBiFYFIeFd3mqgnkCAwEAAaNCMEAw" +
            "HQYDVR0OBBYEFOLJQJ9NzuiaoXzPDj9lxSmIahlRMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEB" +
            "CwUAA4ICAQDRSVfgp8xoWLoBDysZzY2wYUWsEe1jUGn4H3++Fo/9nesLqjJHdtJnJO29fDMylyrHBYZmDRd9FBUb1Ov9H5r2Xpdp" +
            "txolpAqzkT9fNqyL7FeoPueBihhXOYV0GkLH6VsTX4/5COmSdI31R9KrO9b7eGZONn356ZLpBN79SWP8bfsUcZNnL0dKt7n/Hipz" +
            "cEYwv1ryL3ml4Y0M2fmyYzeMN2WFcGpcWwlyua1jPLHd+PwyvzeG5LuOmCd+uh8W4XAR8gPfJWIyJyYYMoSf/wA6E7qaTfRPuBRw" +
            "IrHKK5DOKcFw9C+df/KQHtZa37dG/OaG+svgIHZ6uqbL9XzeYqWxi+7egmaKTjowHz+Ay60nugxe19CxVsp3cbK1daFQqUBDF8Io" +
            "2c9Si1vIY9RCPqAzekYu9wogRlR+ak8x8YF+QnQ4ZXMn7sZ8uI7XpTrXmKGcjBBV09tL7ECQ8s1uV9JiDnxXk7Gnbc2dg7sq5+W2" +
            "O3FYrf3RRbxake5TFW/TRQl1brqQXR4EzzffHqhmsYzmIGrv/EhOdJhCrylvLmrH+33RZjEizIYAfmaDDEL0vTSSwxrqT8p+ck0L" +
            "cIymSLumoRT2+1hEmRSuqguTaaApJUqlyyvdimYHFngVV3Eb7PVHhPOeMTd61X8kreS8/f3MboPoDKi3QWwH3b08hpcv0g==",
        ),
        Root(
            name = "UCA Extended Validation Root",
            owner = "上海數字證書認證中心 SHECA",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "D43AF9B35473755C9684FC06D7D8CB70EE5C28E773FB294EB41EE71722924D24",
            b64 = "MIIFWjCCA0KgAwIBAgIQT9Irj/VkyDOeTzRYZiNwYDANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJDTjERMA8GA1UECgwIVW5p" +
            "VHJ1c3QxJTAjBgNVBAMMHFVDQSBFeHRlbmRlZCBWYWxpZGF0aW9uIFJvb3QwHhcNMTUwMzEzMDAwMDAwWhcNMzgxMjMxMDAwMDAw" +
            "WjBHMQswCQYDVQQGEwJDTjERMA8GA1UECgwIVW5pVHJ1c3QxJTAjBgNVBAMMHFVDQSBFeHRlbmRlZCBWYWxpZGF0aW9uIFJvb3Qw" +
            "ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCpCQcoEwKwmeBkqh5DFnpzsZGgdT6o+uM4AHrsiWogD4vFsJszA1qGxliG" +
            "1cGFu0/GnEBNyr7uaZa4rYEwmnySBesFK5pI0Lh2PpbIILvSsPGP2KxFRv+qZ2C0d35qHzwaUnoEPQc8hQ2E0B92CvdqFN9y4zR8" +
            "V05WAT558aopO2z6+I9tTcg1367r3CTueUWnhbYFiN6IXSV8l2RnCdm/WhUFhvMJHuxYMjMR83dksHYf5BA1FxvyDrFspCqjc/wJ" +
            "Hx4yGVMR59mzLC52LqGj3n5qiAno8geK+LLNEOfic0CTuwjRP+H8C5SzJe98ptfRr5//lpr1kXuYC3fUfugH0mK1lTnj8/FtDw5l" +
            "hIpjVMWAtuCeS31HJqcBCF3RiJ7XwzJE+oJKCmhUfzhTA8ykADNkUVkLo4KRel7sFsLzKuZi2irbWWIQJUoqgQtHB0MGcIfS+pMR" +
            "KXpITeuUx3BNr2fVUbGAIAEBtHoIppB/TuDvB0GHr2qlXov7z1CymlSvw4m6WC31MJixNnI5fkkE/SmnTHnkBVfblLkWU41Gsx2V" +
            "YVdWf6/wFlthWG82UBEL2KwrlRYaDh8IzTY0ZRBiZtWAXxQgXy0MoHgKaNYs1+lvK9JKBZP8nm9rZ/+I8U6laUpSNwXqxhaN0sSZ" +
            "0YIrO7o1dfdRUVjzyAfd5LQDfwIDAQABo0IwQDAdBgNVHQ4EFgQU2XQ65DA9DfcS3H5aBZ8eNJr34RQwDwYDVR0TAQH/BAUwAwEB" +
            "/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBADaNl8xCFWQpN5smLNb7rhVpLGsaGvdftvkHTFnq88nIua7Mui56" +
            "3MD1sC3AO6+fcAURap8lTwEpcOPlDOHqWnzcSbvBHiqB9RZLcpHIojG5qtr8nR/zXUACE/xOHAbKsxSQVBcZEhrxH9cMaVr2cXj0" +
            "lH2RC47skFSOvG+hTKv8dGT9cZr4QQehzZHkPJrgmzI5c6sq1WnIeJEmMX3ixzDx/BR4dxIOE/TdFpS/S2d7cFOFyrC78zhNLJA5" +
            "wA3CXWvp4uXViI3WLL+rG761KIcSF3Ru/H38j9CHJrAb+7lsq+KePRXBOy5nAliRn+/4Qh8st2j1da3Ptfb/EX3C8CSlrdP6oDyp" +
            "+l3cpaDvRKS+1ujl5BOWF3sGPjLtx7dCvHaj2GU4Kzg1USEODm8uNBNA4StnDG1KQTAYI1oyVZnJF+A83vbsea0rWBmirSwiGpWO" +
            "vpaQXUJXxPkUAzUrHC1RVwinOt4/5Mi0A3PCwSaAuwtCH60NryZy2sy+s6ODWA2CxR9GUeOcGMyNm43sSet1UNWMKFnKdDTajAsh" +
            "qx7qG+XH/RU+wBeq+yNuJkbL+vmxcmtpzyKEC2IPrNkZAJSidjzULZrtBJ4tBmIQN1IchXIbJ+XMxjHsN+xjWZsLHXbMfjKaiJUI" +
            "NlK73nZfdklJrX+9ZSCyycErdhh2n1ax",
        ),
        Root(
            name = "UCA Global G2 Root",
            owner = "上海數字證書認證中心 SHECA",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站與電子郵件",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "9BEA11C976FE014764C1BE56A6F914B5A560317ABD9988393382E5161AA0493C",
            b64 = "MIIFRjCCAy6gAwIBAgIQXd+x2lqj7V2+WmUgZQOQ7zANBgkqhkiG9w0BAQsFADA9MQswCQYDVQQGEwJDTjERMA8GA1UECgwIVW5p" +
            "VHJ1c3QxGzAZBgNVBAMMElVDQSBHbG9iYWwgRzIgUm9vdDAeFw0xNjAzMTEwMDAwMDBaFw00MDEyMzEwMDAwMDBaMD0xCzAJBgNV" +
            "BAYTAkNOMREwDwYDVQQKDAhVbmlUcnVzdDEbMBkGA1UEAwwSVUNBIEdsb2JhbCBHMiBSb290MIICIjANBgkqhkiG9w0BAQEFAAOC" +
            "Ag8AMIICCgKCAgEAxeYrb3zvJgUno4Ek2m/LAfmZmqkywiKHYUGRO8vDaBsGxUypK8FnFyIdK+35KYmToni9kmugow2ifsqTs6bR" +
            "jDXVdfkX9s9FxeV67HeToI8jrg4aA3++1NDtLnurRiNb/yzmVHqUwCoV8MmNsHo7JOHXaOIxPAYzRrZUEaalLyJUKlgNAQLx+hVR" +
            "Z2zA+te2G3/RVogvGjqNO7uCEeBHANBSh6v7hn4PJGtAnTRnvI3HLYZveT6OqTwXS3+wmeOwcWDcC/Vkw85DvG1xudLeJ1uK6NjG" +
            "ruFZfc8oLTW4lVYa8bJYS7cSN8h8s+1LgOGN+jIjtm+3SJUIsUROhYw6AlQgL9+/V087OpAh18EmNVQg7Mc/R+zvWr9LesGtOxdQ" +
            "XGLYD0tK3Cv6brxzks3sx1DoQZbXqX5t2Okdj4q1uViSukqSKwxW/YDrCPBeKW4bHAyvj5OJrdu9o54hyokZ7N+1wxrrFv54NkzW" +
            "btA+FxyQF2smuvt6L78RHBgOLXMDj6DlNaBa4kx1HXHhOThTeEDMg5PXCp6dW4+K5OXgSORIskfNTip1KnvyIvbJvgmRlld6iIis" +
            "7nCs+dwp4wwcOxJORNanTrAmyPPZGpeRaOrvjUYG0lZFWJo8DA+DuAUlwznPO6Q0ibd5Ei9Hxeepl2n8pndntd978XplFeRhVmUC" +
            "AwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIHEjMz15DD/pQwIX4wVZyF0Ad/fMA0G" +
            "CSqGSIb3DQEBCwUAA4ICAQATZSL1jiutROTL/7lo5sOASD0Ee/ojL3rtNtqyzm325p7lX1iPyzcyochltq44PTUbPrw7tgTQvPlJ" +
            "9Zv3hcU2tsu8+Mg51eRfB70VVJd0ysrtT7q6ZHafgbiERUlMjW+i67HM0cOU2kTC5uLqGOiiHycFutfl1qnN3e92mI0ADs0b+gO3" +
            "joBYDic/UvuUospeZcnWhNq5NXHzJsBPd+aBJ9J3O5oUb3n09tDh05S60FdRvScFDcH9yBIw7m+NESsIndTUv4BFFJqIRNow6rSn" +
            "4+7vW4LVPtateJLbXDzz2K36uGt/xDYotgIVilQsnLAXc47QN6MUPJiVAAwpBVueSUmxX8fjy88nZY41F7dXyDDZQVu5FLbowg+U" +
            "MaeUmMxq67XhJ/UQqAHojhJi6IjMtX9Gl8CbEGY4GjZGXyJoPd/JxhMnq1MGrKI8hgZlb7F+sSlEmqO6SWkoaY/X5V+tBIZkbxqg" +
            "DMUIYs6Ao9Dz7GjevjPHF1t/gMRMTLGmhIrDO7gJzRSBuhjjVFc2/tsvfEehOjPI+Vg7RE+xygKJBJYoaMVLuCaJu9YzL1DV/pqJ" +
            "uhgyklTGW+Cd+V7lDSKb9triyCGyYiGqhkCyLmTTX8jjfhFnRR8F/uOi77Oos/N9j/gMHyIfLXC0uAE0djAA5SN4p1bXUB+K+wb1" +
            "whnw0A==",
        ),
        Root(
            name = "BJCA Global Root CA1",
            owner = "北京數字認證 BJCA",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "F3896F88FE7C0A882766A7FA6AD2749FB57A7F3E98FB769C1FA7B09C2C44D5AE",
            b64 = "MIIFdDCCA1ygAwIBAgIQVW9l47TZkGobCdFsPsBsIDANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJDTjEmMCQGA1UECgwdQkVJ" +
            "SklORyBDRVJUSUZJQ0FURSBBVVRIT1JJVFkxHTAbBgNVBAMMFEJKQ0EgR2xvYmFsIFJvb3QgQ0ExMB4XDTE5MTIxOTAzMTYxN1oX" +
            "DTQ0MTIxMjAzMTYxN1owVDELMAkGA1UEBhMCQ04xJjAkBgNVBAoMHUJFSUpJTkcgQ0VSVElGSUNBVEUgQVVUSE9SSVRZMR0wGwYD" +
            "VQQDDBRCSkNBIEdsb2JhbCBSb290IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPFmCL3ZxRVhy4QEQaVpN3cd" +
            "wbB7+sN3SJATcmTRuHyQNZ0YeYjjlwE8R4HyDqKYDZ4/N+AZspDyRhySsTphzvq3Rp4Dhtczbu33RYx2N95ulpH3134rhxfVizXu" +
            "hJFyV9xgw8O558dnJCNPYwpj9mZ9S1WnP3hkSWkSl+BMDdMJoDIwOvqfwPKcxRIqLhy1BDPapDgRat7GGPZHOiJBhyL8xIkoVNiM" +
            "pTAK+BcWyqw3/XmnkRd4OJmtWO2y3syJfQOcs4ll5+M7sSKGjwZteAf9kRJ/sGsciQ35uMt0WwfCyPQ10WRjeulumijWML3mG90V" +
            "r4TqnMfK9Q7q8l0ph49pczm+LiRvRSGsxdRpJQaDrXpIhRMsDQa4bHlW/KNnMoH1V6XKV0Jp6VwkYe/iMBhORJhVb3rCk9gZtt58" +
            "R4oRTklH2yiUAguUSiz5EtBP6DF+bHq/pj+bOT0CFqMYs2esWz8sgytnOYFcuX6U1WTdno9uruh8W7TXakdI136z1C2OVnZOz2nx" +
            "bkRs1CTqjSShGL+9V/6pmTW12xB3uD1IutbB5/EjPtffhZ0nPNRAvQoMvfXnjSXWgXSHRtQpdaJCbPdzied9v3pKH9MiyRVVz99v" +
            "fFXQpIsHETdfg6YmV6YBW37+WGgHqel62bno/1Afq8K0wM7o6v0PvY1NuLxxAgMBAAGjQjBAMB0GA1UdDgQWBBTF7+3M2I0hxkjk" +
            "49cULqcWk+WYATAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAUoKsITQfI/Ki2Pm4" +
            "rzc2IInRNwPWaZ+4YRC6ojGYWUfo0Q0lHhVBDOAqVdVXUsv45Mdpox1NcQJeXyFFYEhcCY5JEMEE3KliawLwQ8hOnThJdMkycFRt" +
            "wUf8jrQ2ntScvd0g1lPJGKm1Vrl2i5VnZu69mP6u775u+2D2/VnGKhs/I0qUJDAnyIm860Qkmss9vk/Ves6OF8tiwdneHg56/0OG" +
            "NFK8YT88X7vZdrRTvJez/opMEi4r89fO4aL/3Xtw+zuhTaRjAv04l5U/BXCga99igUOLtFkNSoxUnMW7gZ/NfaXvCyUeOiDbHPwf" +
            "mGcCCtRzRBPbUYQaVQNW4AB+dAb/OMRyHdOoP2gxXdMJxy6MW2Pg6Nwe0uxhHvLe5e/2mXZgLR6UcnHGCyoyx5JO1UbXHfmpGQrI" +
            "+pXObSOYqgs4rZpWDW+N8TEAiMEXnM0ZNjX+VVOg4DwzX5Ze4jLp3zO7Bkqp2IRzznfSxqxx4VyjHQy7Ct9f4qNx2No3WqB4K/TU" +
            "fet27fJhcKVlmtOJNBir+3I+17Q9eVzYH6Eze9mCUAyTF6ps3MKCuwJXNq+YJyo5UOGwifUll35HaBC07HPKs5fRJNz2YqAo07Wj" +
            "uGS3iGJCz51TzZm+ZGiPTx4SSPfSKcOYKMryMguTjClPPGAyzQWWYezyr/6zcCwupvI=",
        ),
        Root(
            name = "BJCA Global Root CA2",
            owner = "北京數字認證 BJCA",
            group = Group.MAINLAND_CHINA,
            algorithm = "ECC secp384r1",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "574DF6931E278039667B720AFDC1600FC27EB66DD3092979FB73856487212882",
            b64 = "MIICJTCCAaugAwIBAgIQLBcIfWQqwP6FGFkGz7RK6zAKBggqhkjOPQQDAzBUMQswCQYDVQQGEwJDTjEmMCQGA1UECgwdQkVJSklO" +
            "RyBDRVJUSUZJQ0FURSBBVVRIT1JJVFkxHTAbBgNVBAMMFEJKQ0EgR2xvYmFsIFJvb3QgQ0EyMB4XDTE5MTIxOTAzMTgyMVoXDTQ0" +
            "MTIxMjAzMTgyMVowVDELMAkGA1UEBhMCQ04xJjAkBgNVBAoMHUJFSUpJTkcgQ0VSVElGSUNBVEUgQVVUSE9SSVRZMR0wGwYDVQQD" +
            "DBRCSkNBIEdsb2JhbCBSb290IENBMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABJ3LgJGNU2e1uVCxA/jlSR9BIgmwUVJY1is0j8US" +
            "RhTFiy8shP8sbqjV8QnjAyEUxEM9fMEsxEtqSs3ph+B99iK++kpRuDCK/eHeGBIK9ke35xe/J4rUQUyWPGCWwf0VHKNCMEAwHQYD" +
            "VR0OBBYEFNJKsVF/BvDRgh9Obl+rg/xI1LCRMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA" +
            "MGUCMBq8W9f+qdJUDkpd0m2xQNz0Q9XSSpkZElaA94M04TVOSG0ED1cxMDAtsaqdAzjbBgIxAMvMh1PLet8gUXOQwKhbYdDFUDn9" +
            "hf7B43j4ptZLvZuHjw/l1lOWqzzIQNph91Oj9w==",
        ),
        Root(
            name = "vTrus ECC Root CA",
            owner = "天威誠信 iTrusChina",
            group = Group.MAINLAND_CHINA,
            algorithm = "ECC secp384r1",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "30FBBA2C32238E2A98547AF97931E550428B9B3F1C8EEB6633DCFA86C5B27DD3",
            b64 = "MIICDzCCAZWgAwIBAgIUbmq8WapTvpg5Z6LSa6Q75m0c1towCgYIKoZIzj0EAwMwRzELMAkGA1UEBhMCQ04xHDAaBgNVBAoTE2lU" +
            "cnVzQ2hpbmEgQ28uLEx0ZC4xGjAYBgNVBAMTEXZUcnVzIEVDQyBSb290IENBMB4XDTE4MDczMTA3MjY0NFoXDTQzMDczMTA3MjY0" +
            "NFowRzELMAkGA1UEBhMCQ04xHDAaBgNVBAoTE2lUcnVzQ2hpbmEgQ28uLEx0ZC4xGjAYBgNVBAMTEXZUcnVzIEVDQyBSb290IENB" +
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZVBKrox5lkqqHAjDo6LN/llWQXf9JpRCux3NCNtzslt188+cToL0v/hhJoVs1oVbcnDS" +
            "/dtitN9Ti72xRFhiQgnH+n9bEOf+QP3A2MMrMudwpremIFUde4BdS49nTPEQo0IwQDAdBgNVHQ4EFgQUmDnNvtiyjPeyq+GtJK97" +
            "fKHbH88wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwV53dVvHH4+m4SVBrm2nDb+zD" +
            "fSXkV5UTQJtS0zvzQBm8JsctBp61ezaf9SXUY2sAAjEA6dPGnlaaKsyh2j/IZivTWJwghfqrkYpwcBE4YGQLYgmRWAD5Tfs0aNoJ" +
            "rSEGGJTO",
        ),
        Root(
            name = "vTrus Root CA",
            owner = "天威誠信 iTrusChina",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "8A71DE6559336F426C26E53880D00D88A18DA4C6A91F0DCB6194E206C5C96387",
            b64 = "MIIFVjCCAz6gAwIBAgIUQ+NxE9izWRRdt86M/TX9b7wFjUUwDQYJKoZIhvcNAQELBQAwQzELMAkGA1UEBhMCQ04xHDAaBgNVBAoT" +
            "E2lUcnVzQ2hpbmEgQ28uLEx0ZC4xFjAUBgNVBAMTDXZUcnVzIFJvb3QgQ0EwHhcNMTgwNzMxMDcyNDA1WhcNNDMwNzMxMDcyNDA1" +
            "WjBDMQswCQYDVQQGEwJDTjEcMBoGA1UEChMTaVRydXNDaGluYSBDby4sTHRkLjEWMBQGA1UEAxMNdlRydXMgUm9vdCBDQTCCAiIw" +
            "DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL1VfGHTuB0EYgWgrmy3cLRB6ksDXhA/kFocizuwZotsSKYcIrrVQJLuM7IjWcmO" +
            "vFjai57QGfIvWcaMY1q6n6MLsLOaXLoRuBLpDLvPbmyAhykUAyyNJJrIZIO1aqwTLDPxn9wsYTwaP3BVm60AUn/PBLn+NvqcwBau" +
            "Yv6WTEN+VRS+GrPSbcKvdmaVayqwlHeFXgQPYh1jdfdr58tbmnDsPmcF8P4HCIDPKNsFxhQnL4Z98Cfe/+Z+M0jnCx5Y0ScrUw5X" +
            "SmXX+6KAYPxMvDVTAWqXcoKv8R1w6Jz1717CbMdHflqUhSZNO7rrTOiwCcJlwp2dCZtOtZcFrPUGoPc2BX70kLJrxLT5ZOrpGgrI" +
            "DajtJ8nU57O5q4IikCc9Kuh8kO+8T/3iCiSn3mUkpF3qwHYw03dQ+A0Em5Q2AXPKBlim0zvc+gRGE1WKyURHuFE5Gi7oNOJ5y1lK" +
            "Cn+8pu8fA2dqWSslYpPZUxlmPCdiKYZNpGvu/9ROutW04o5IWgAZCfEF2c6Rsffr6TlP9m8EQ5pV9T4FFL2/s1m02I4zhKOQUqqz" +
            "ApVg+QxMaPnu1RcN+HFXtSXkKe5lXa/R7jwXC1pDxaWG6iSe4gUH3DRCEpHWOXSuTEGC2/KmSNGzm/MzqvOmwMVO9fSddmPmAsYi" +
            "S8GVP1BkLFTltvA8Kc9XAgMBAAGjQjBAMB0GA1UdDgQWBBRUYnBj8XWEQ1iO0RYgscasGrz2iTAPBgNVHRMBAf8EBTADAQH/MA4G" +
            "A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAKbqSSaet8PFww+SX8J+pJdVrnjT+5hpk9jprUrIQeBqfTNqK2uwcN1Lg" +
            "Qkv7bHbKJAs5EhWdnxEt/Hlk3ODg9d3gV8mlsnZwUKT+twpw1aA08XXXTUm6EdGz2OyC/+sOxL9kLX1jbhd47F18iMjrjld22VkE" +
            "+rxSH0Ws8HqA7Oxvdq6R2xCOBNyS36D25q5J08FsEhvMKar5CKXiNxTKsbhm7xqC5PD48acWabfbqWE8n/Uxy+QARsIvdLGx14Hu" +
            "qCaVvIivTDUHKgLKeBRtRytAVunLKmChZwOgzoy8sHJnxDHO2zTlJQNgJXtxmOTAGytfdELSS8VZCAeHvsXDf+eW2eHcKJfWjwXj" +
            "9ZtOyh1QRwVTsMo554WgicEFOwE30z9J4nfrI8iIZjs9OXYhRvHsXyO466JmdXTBQPfYaJqT4i2pLr0cox7IdMakLXogqzu4sEb9" +
            "b91fUlV1YvCXoHzXOP0l382gmxDPi7g4Xl7FtKYCNqEeXxzP4padKar9mK5S4fNBUvupLnKWnyfjqnN9+BojZns7q2WwMgFLFT49" +
            "ok8MKzWixtlnEjUwzXYuFrOZnk1PTi07NEPhmg4NpGaXutIcSkwsKouLgU9xGqndXHt7CMUADTdA43x7VF8vhV929vensBxXVsFy" +
            "6K2ir40zSbofitzmdHxghm+Hl3s=",
        ),
        Root(
            name = "TrustAsia Global Root CA G3",
            owner = "亞洲誠信 TrustAsia",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "E0D3226AEB1163C2E48FF9BE3B50B4C6431BE7BB1EACC5C36B5D5EC509039A08",
            b64 = "MIIFpTCCA42gAwIBAgIUZPYOZXdhaqs7tOqFhLuxibhxkw8wDQYJKoZIhvcNAQEMBQAwWjELMAkGA1UEBhMCQ04xJTAjBgNVBAoM" +
            "HFRydXN0QXNpYSBUZWNobm9sb2dpZXMsIEluYy4xJDAiBgNVBAMMG1RydXN0QXNpYSBHbG9iYWwgUm9vdCBDQSBHMzAeFw0yMTA1" +
            "MjAwMjEwMTlaFw00NjA1MTkwMjEwMTlaMFoxCzAJBgNVBAYTAkNOMSUwIwYDVQQKDBxUcnVzdEFzaWEgVGVjaG5vbG9naWVzLCBJ" +
            "bmMuMSQwIgYDVQQDDBtUcnVzdEFzaWEgR2xvYmFsIFJvb3QgQ0EgRzMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDA" +
            "MYJhkuSUGwoqZdC+BqmHO1ES6nBBruL7dOoKjbmzTNyPtxNST1QY4SxzlZHFZjtqz6xjbYdT8PfxObegQ2OwxANdV6nnRM7EoYNl" +
            "9lA+sX4WuDqKAtCWHwDNBSHvBm3dIZwZQ0WhxeiAysKtQGIXBsaqvPPW5vxQfmZCHzyLpnl5hkA1nyDvP+uLRx+PjsXUjrYsyUQE" +
            "49RDdT/VP68czH5GX6zfZBCK70bwkPAPLfSIC7Epqq+FqklYqL9joDiR5rPmd2jE+SoZhLsO4fWvieylL1AgdB4SQXMeJNnKziyh" +
            "WTXAyB1GJ2Faj/lN03J5Zh6fFZAhLf3ti1ZwA0pJPn9pMRJpxx5cynoTi+jm9WAPzJMshH/x/Gr8m0ed262IPfN2dTPXS6TIi/n1" +
            "Q1hPy8gDVI+lhXgEGvNz8teHHUGf59gXzhqcD0r83ERoVGjiQTz+LISGNzzNPy+i2+f3VANfWdP3kXjHi3dqFuVJhZBFcnAvkV34" +
            "PmVACxmZySYgWmjBNb9Pp1Hx2BErW+Canig7CjoKH8GB5S7wprlppYiU5msTf9FkPz2ccEblooV7WIQn3MSAPmeamseaMQ4w7OYX" +
            "QJXZRe0Blqq/DPNL0WP3E1jAuPP6Z92bfW1K/zJMtSU7/xxnD4UiWQWRkUF3gdCFTIcQcf+eQxuulXUtgQIDAQABo2MwYTAPBgNV" +
            "HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFEDk5PIj7zjKsK5Xf/IhMBY027ySMB0GA1UdDgQWBBRA5OTyI+84yrCuV3/yITAWNNu8" +
            "kjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEMBQADggIBACY7UeFNOPMyGLS0XuFlXsSUT9SnYaP4wM8zAQLpw6o1D/GUE3d3" +
            "NZ4tVlFEbuHGLige/9rsR82XRBf34EzC4Xx8MnpmyFq2XFNFV1pF1AWZLy4jVe5jaN/TG3inEpQGAHUNcoTpLrxaatXeL1nHo+zS" +
            "h2bbt1S1JKv0Q3jbSwTEb93mPmY+KfJLaHEih6D4sTNjduMNhXJEIlU/HHzp/LgV6FL6qj6jITk1dImmasI5+njPtqzn59ZW/yOS" +
            "LlALqbUHM/Q4X6RJpstlcHboCoWASzY9M/eVVHUl2qzEc4Jl6VL1XP04lQJqaTDFHApXB64ipCz5xUG3uOyfT0gA+QEEVcys+TIx" +
            "xHWVBqB/0Y0n3bOppHKH/lmLmnp0Ft0WpWIp6zqW3IunaFnT63eROfjXy9mPX1onAX1daBli2MjN9LdyR75bl87yraKZk62Uy5P2" +
            "EgmVtqvXO9A/EcswFi55gORngS1d7XB4tmBZrOFdRWOPyN9yaFvqHbgB8X7754qz41SgOAngPN5C8sLtLpvzHzW2NtjjgKGLzZlk" +
            "D8Kqq7HK9W+eQ42EVJmzbsASZthwEPEGNTNDqJwuuhQxzhB/HIbjj9LV+Hfsm6vxL2PZQl/gZ4FkkfGXL/xuJvYz+NO1+MRiqzFR" +
            "JQJ6+N1rZdVtTTDIZbpoFGWsJwt0ivKH",
        ),
        Root(
            name = "TrustAsia Global Root CA G4",
            owner = "亞洲誠信 TrustAsia",
            group = Group.MAINLAND_CHINA,
            algorithm = "ECC secp384r1",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "BE4B56CB5056C0136A526DF444508DAA36A0B54F42E4AC38F72AF470E479654C",
            b64 = "MIICVTCCAdygAwIBAgIUTyNkuI6XY57GU4HBdk7LKnQV1tcwCgYIKoZIzj0EAwMwWjELMAkGA1UEBhMCQ04xJTAjBgNVBAoMHFRy" +
            "dXN0QXNpYSBUZWNobm9sb2dpZXMsIEluYy4xJDAiBgNVBAMMG1RydXN0QXNpYSBHbG9iYWwgUm9vdCBDQSBHNDAeFw0yMTA1MjAw" +
            "MjEwMjJaFw00NjA1MTkwMjEwMjJaMFoxCzAJBgNVBAYTAkNOMSUwIwYDVQQKDBxUcnVzdEFzaWEgVGVjaG5vbG9naWVzLCBJbmMu" +
            "MSQwIgYDVQQDDBtUcnVzdEFzaWEgR2xvYmFsIFJvb3QgQ0EgRzQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATxs8045CVD5d4ZCbuB" +
            "eaIVXxVjAd7Cq92zphtnS4CDr5nLrBfbK5bKfFJV4hrhPVbwLxYI+hW8m7tH5j/uqOFMjPXTNvk4XatwmkcN4oFBButJ+bAp3TPs" +
            "UKV/eSm4IJijYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUpbtKl86zK3+kMd6Xg1mDpm9xy94wHQYDVR0OBBYEFKW7" +
            "SpfOsyt/pDHel4NZg6ZvccveMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNnADBkAjBe8usGzEkxn0AAbbd+NvBNEU/zy4k6" +
            "LHiRUKNbwMp1JvK/kF0LgoxgKJ/GcJpo5PECMFxYDlZ2z1jD1xCMuo6u47xkdUfFVZDj/bpV6wfEU6s3qe4hsiFbYI89MvHVI5TW" +
            "WA==",
        ),
        Root(
            name = "TrustAsia TLS ECC Root CA",
            owner = "亞洲誠信 TrustAsia",
            group = Group.MAINLAND_CHINA,
            algorithm = "ECC secp384r1",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "C0076B9EF0531FB1A656D67C4EBE97CD5DBAA41EF44598ACC2489878C92D8711",
            b64 = "MIICMTCCAbegAwIBAgIUNnThTXxlE8msg1UloD5Sfi9QaMcwCgYIKoZIzj0EAwMwWDELMAkGA1UEBhMCQ04xJTAjBgNVBAoTHFRy" +
            "dXN0QXNpYSBUZWNobm9sb2dpZXMsIEluYy4xIjAgBgNVBAMTGVRydXN0QXNpYSBUTFMgRUNDIFJvb3QgQ0EwHhcNMjQwNTE1MDU0" +
            "MTU2WhcNNDQwNTE1MDU0MTU1WjBYMQswCQYDVQQGEwJDTjElMCMGA1UEChMcVHJ1c3RBc2lhIFRlY2hub2xvZ2llcywgSW5jLjEi" +
            "MCAGA1UEAxMZVHJ1c3RBc2lhIFRMUyBFQ0MgUm9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLh/pVs/AT598IhtrimY4Ztc" +
            "U5nb9wj/1WrgjstEpvDBjL1P1M7UiFPoXlfXTr4sP/MSpwDpguMqWzJ8S5sUKZ74LYO1644xST0mYekdcouJtgq7nDM1D9rs3qlK" +
            "H8kzsaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQULIVTu7FDzTLqnqOH/qKYqKaT6RAwDgYDVR0PAQH/BAQDAgEGMAoG" +
            "CCqGSM49BAMDA2gAMGUCMFRH18MtYYZI9HlaVQ01L18N9mdsd0AaRuf4aFtOJx24mH1/k78ITcTaRTChD15KeAIxAKORh/IRM4PD" +
            "wYqROkwrULG9IpRdNYlzg8WbGf60oenUoWa2AaU2+dhoYSi3dOGiMQ==",
        ),
        Root(
            name = "TrustAsia TLS RSA Root CA",
            owner = "亞洲誠信 TrustAsia",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "網站",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "06C08D7DAFD876971EB1124FE67F847EC0C7A158D3EA53CBE940E2EA9791F4C3",
            b64 = "MIIFgDCCA2igAwIBAgIUHBjYz+VTPyI1RlNUJDxsR9FcSpwwDQYJKoZIhvcNAQEMBQAwWDELMAkGA1UEBhMCQ04xJTAjBgNVBAoT" +
            "HFRydXN0QXNpYSBUZWNobm9sb2dpZXMsIEluYy4xIjAgBgNVBAMTGVRydXN0QXNpYSBUTFMgUlNBIFJvb3QgQ0EwHhcNMjQwNTE1" +
            "MDU0MTU3WhcNNDQwNTE1MDU0MTU2WjBYMQswCQYDVQQGEwJDTjElMCMGA1UEChMcVHJ1c3RBc2lhIFRlY2hub2xvZ2llcywgSW5j" +
            "LjEiMCAGA1UEAxMZVHJ1c3RBc2lhIFRMUyBSU0EgUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMMWuBtq" +
            "pERz5dZO9LnPWwvB0ZqB9WOwj0PBuwhaGnrhB3YmH49pVr7+NmDQDIPNlOrnxS1cLwUWAp4KqC/lYCZUlviYQB2srp10Zy9U+5Rj" +
            "mOMmSoPGlbYJQ1DNDX3eRA5gEk9bNb2/mThtfWza4mhzH/kxpRkQcwUqwzIZheo0qt1CHjCNP561HmHVb70AcnKtEj+qpklz8oYV" +
            "lQwQX1Fkzv93uMltrOXVmPGZLmzjyUT5tUMnCE32ft5EebuyjBza00tsLtbDeLdM1aTk2tyKjg7/D8OmYCYozza/+lcK7Fs/6TAW" +
            "e8TbxNRkoDD75f0dcZLdKY9BWN4ArTr9PXwaqLEX8E40eFgl1oUh63kd0Nyrz2I8sMeXi9bQn9P+PN7F4/w6g3CEIR0JwqH8uygh" +
            "ZVNgepBtljhb//HXeltt08lwSUq6HTrQUNoyIBnkiz/r1RYmNzz7dZ6wB3C4FGB33PYPXFIKvF1tjVEK2sUYyJtt3LCDs3+jTnhM" +
            "mCWr8n4uIF6CFabW2I+s5c0yhsj55NqJ4js+k8UTav/H9xj8Z7XvGCxUq0DTbE3txci3OE9kxJRMT6DNrqXGJyV1J23G2pyOsAWZ" +
            "1SgRxSHUuPzHlqtKZFlhaxP8S8ySpg+kUb8OWJDZgoM5pl+z+m6Ss80zDoWo8SnTq1mt1tve1CuBAgMBAAGjQjBAMA8GA1UdEwEB" +
            "/wQFMAMBAf8wHQYDVR0OBBYEFLgHkXlcBvRG/XtZylomkadFK/hTMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQwFAAOCAgEA" +
            "IZtqBSBdGBanEqT3Rz/NyjuujsCCztxIJXgXbODgcMTWltnZ9r96nBO7U5WS/8+S4PPFJzVXqDuiGev4iqME3mmL5Dw8veWv0BIb" +
            "5Ylrc5tvJQJLkIKvQMKtuppgJFqBTQUYo+IzeXoLH5Pt7DlK9RME7I10nYEKqG/odv6LTytpEoYKNDbdgptvT+Bz3Ul/KD7JO6NX" +
            "BNiT2Twp2xIQaOHEibgGIOcberyxk2GaGUARtWqFVwHxtlotJnMnlvm5P1vQiJ3koP26TpUJg3933FEFlJ0gcXax7PqJtZwuhfG5" +
            "WyRasQmr2soaB82G39tp27RIGAAtvKLEiUUjpQ7hRGU+isFqMB3iYPg6qocJQrmBktwliJiJ8Xw18WLK7nn4GS/+X/jbh87qqA8M" +
            "pugLoDzga5SYnH+tBuYc6kIQX+ImFTw3OffXvO645e8D7r0i+yiGNFjEWn9hongPXvPKnbwbPKfILfanIhHKA9jnZwqKDss1jjQ5" +
            "2MjqjZ9k4DewbNfFj8GQYSbbJIweSsCI3zWQzj8C9GRh3sfIB5XeMhg6j6JCQCTl1jNdfK7vsU1P1FeQNWrcrgSXSYk0ly4wBOeY" +
            "99sLAZDBHwo/+ML+TvrbmnNzFrwFuHnYWa8G5z9nODmxfKuU4CkUpijy323imttUQ/hHWKNddBWcwauwxzQ=",
        ),
        Root(
            name = "TrustAsia SMIME ECC Root CA",
            owner = "亞洲誠信 TrustAsia",
            group = Group.MAINLAND_CHINA,
            algorithm = "ECC secp384r1",
            purposes = "電子郵件與文件簽章",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "436472C1009A325C54F1A5BBB5468A7BAEECCBE05DE5F099CB70D3FE41E13C16",
            b64 = "MIICNjCCAbugAwIBAgIUWsL4KU/jfcVeHRhvO5MgH/97ui0wCgYIKoZIzj0EAwMwWjELMAkGA1UEBhMCQ04xJTAjBgNVBAoTHFRy" +
            "dXN0QXNpYSBUZWNobm9sb2dpZXMsIEluYy4xJDAiBgNVBAMTG1RydXN0QXNpYSBTTUlNRSBFQ0MgUm9vdCBDQTAeFw0yNDA1MTUw" +
            "NTQxNTlaFw00NDA1MTUwNTQxNThaMFoxCzAJBgNVBAYTAkNOMSUwIwYDVQQKExxUcnVzdEFzaWEgVGVjaG5vbG9naWVzLCBJbmMu" +
            "MSQwIgYDVQQDExtUcnVzdEFzaWEgU01JTUUgRUNDIFJvb3QgQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATN2fsnvWnshsmQQ7Fw" +
            "F5SnyXcjOj8jZdMcox0eQlQg69BCu1m5i6zyho1Ljh2qliIjOXZtkpvrIst6Q6Jz/XNLwiUPKrFpxv9F36k8lYC7qR5Kky/sHB2I" +
            "9BGSN583mHKjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFDFn5nKyDeYioKzPfiKnWTLjZiOlMA4GA1UdDwEB/wQEAwIB" +
            "BjAKBggqhkjOPQQDAwNpADBmAjEA3TpMjaTGf+29pcZPPv0xSyjWilbfZRZ3h037ujIIgeCeM0iLn5SG7wErlOaM1tSOAjEAn4Gc" +
            "sCb9K9by9XGEnqjHiozWWBFStbgEy8xxdWPixhk42W1sGXGkFhkhk7oGRChs",
        ),
        Root(
            name = "TrustAsia SMIME RSA Root CA",
            owner = "亞洲誠信 TrustAsia",
            group = Group.MAINLAND_CHINA,
            algorithm = "RSA 4096",
            purposes = "電子郵件與文件簽章",
            source = "CCADB（Mozilla 根憑證計畫）",
            sha256 = "C7796BEB62C101BB143D262A7C96A0C6168183223EF50D699632D86E03B8CC9B",
            b64 = "MIIFhDCCA2ygAwIBAgIUWu5x394MV4W1uzYi17h2RgJzyv8wDQYJKoZIhvcNAQEMBQAwWjELMAkGA1UEBhMCQ04xJTAjBgNVBAoT" +
            "HFRydXN0QXNpYSBUZWNobm9sb2dpZXMsIEluYy4xJDAiBgNVBAMTG1RydXN0QXNpYSBTTUlNRSBSU0EgUm9vdCBDQTAeFw0yNDA1" +
            "MTUwNTQyMDFaFw00NDA1MTUwNTQyMDBaMFoxCzAJBgNVBAYTAkNOMSUwIwYDVQQKExxUcnVzdEFzaWEgVGVjaG5vbG9naWVzLCBJ" +
            "bmMuMSQwIgYDVQQDExtUcnVzdEFzaWEgU01JTUUgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCY" +
            "lZytPFlz05N2pkhUphyIckxN4YL/GhMfUN6M2ZBC0byZ0zej13E6yt1eG5BhQm6PQAFzfR8xutQdbgTSqpCESjMKRJ9aGR+0bi1o" +
            "/K/An0oQEr8+gsKCsC/nkG+QZBCD7Ow2lAx8T+ACDT2HeUJNAOUwrnAfFf36z1IlNk15ILvxEJjgYIfJ9XgMIu0C5hFs8ZtakRF0" +
            "htD+eJKWBMOY78Zwr6mQqhb2Iu3Y+kYoceLJCMBQvHajui2W8hH5pL0QVvgnbStLZIjcF13PAAiKkq4azBLX3/AQKPPNOuo6Eowb" +
            "52EJQ2rkOOn+dDnbzQo7w09T1q5x1TiDhx/O50zzEVWH37ev9+sahhBtqO1I3TLQ26oqC3J3KXf9eug/eCAqaL7ebwjmtYVHgDf5" +
            "cZaLpZhWl3wRZRaO1M7YJ9T5WsWnjbvRNw2lq2Vd2nSTiF7bdfZ/m8KasW0IAgyYSrvNMK92NQKFViNRCUAJBffwPR7CyHoausVB" +
            "FbkNdrS0pLhF/Y2jOz0DKs2zlX80e92hT9k6/yf1DcIBnP9ZdVoayefS/X9PD7X+DTzmoNb7tXZctDBNED/+4utaDrFPT1B+CDMC" +
            "kVcySYmnQBBQF2ufY7qyslaYdvT/cukEnNSnTE/2Oh9aVDFvy7oyrfhtr0XHe2NE38L9eOhKirB0dRbejwIDAQABo0IwQDAPBgNV" +
            "HRMBAf8EBTADAQH/MB0GA1UdDgQWBBSAGqpDwcl/ixqWRbw9u2tIUmxbqzAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEMBQAD" +
            "ggIBACp1gaGCIOp/Vq4JMJcQePTZQBRSpO5qf/AJKNYQY+BOe8kxxwilF+uvhuKXB0+pDqKFzO2kgIEdWlMGPEwaqbeEhs989YUK" +
            "cJnQ7TaRjed3Ls6EnCiGLSU1jEwB5n3bYV3id4TTAdFi3QyiCmSk/PDtOkjyOew11qF6F3Hs09LsuCb7rRVwVkrPZMC5YFv35s2g" +
            "wgMr+bLl2rqlNxzYjdp5dCpn5KJ6xyyNpcFqgWzM9ak5aiJ9ouIIzemT27rLH3V3nveYrxTkO6BMp3LntV5TScz/klfxWSsJuulS" +
            "k8APRQth1mxZcwvY+QEv2gNPNxz034NeC0GgsXw5AKFs0Ni0kXIrGz+imtHE3yvVyJV9hM12G9zkJMY/FSI9hadCK+1+cVlhSMI9" +
            "kWNAfCmzgBYKJfwYYA5TrQ4qzvxBOs2x5GprzDltyE1luKqTiHhuDwKL4JaOdB/QfuF0t/aBauQjrI79jzUdmnEKTypVL/4YwQD3" +
            "e0iKZa9vCB1D51q4H6ToA+v9TLW0k6gx3kOdEr3n6aTS32/8b0aj7zFOjRerG6ng+Kk0VqEO53TsqIeF2Hc1S40+bnJ8SMwfcrNx" +
            "dNQkhrzIwON5FAHO2fqBxlyz+V0MOL7O8o6NXz0l4VE5I6jqAI4Es79yoMK6g/vNpJd1IJq/p1Di3a0sH/Q/o8gx",
        ),
        Root(
            name = "DigiCert Global Root G2",
            owner = "DigiCert",
            group = Group.SERVICE,
            algorithm = "RSA 2048",
            purposes = "國家稅務總局電子稅務局（etax.chinatax.gov.cn）的網站憑證鏈",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F",
            b64 = "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln" +
            "aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0x" +
            "MzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT" +
            "EHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" +
            "MIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULec" +
            "YxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hd" +
            "G82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9" +
            "g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB" +
            "/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9" +
            "PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/J" +
            "sw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FB" +
            "cf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyN" +
            "xF1WW6LZZm6zNTflMrY=",
        ),
        Root(
            name = "TWCA Root Certification Authority",
            owner = "台灣網路認證 TWCA",
            group = Group.SERVICE,
            algorithm = "RSA 2048",
            purposes = "財政部電子發票整合服務平台（einvoice.nat.gov.tw）的網站憑證鏈",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "BFD88FE1101C41AE3E801BF8BE56350EE9BAD1A6B9BD515EDC5C6D5B8711AC44",
            b64 = "MIIDezCCAmOgAwIBAgIBATANBgkqhkiG9w0BAQUFADBfMQswCQYDVQQGEwJUVzESMBAGA1UECgwJVEFJV0FOLUNBMRAwDgYDVQQL" +
            "DAdSb290IENBMSowKAYDVQQDDCFUV0NBIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwODI4MDcyNDMzWhcNMzAx" +
            "MjMxMTU1OTU5WjBfMQswCQYDVQQGEwJUVzESMBAGA1UECgwJVEFJV0FOLUNBMRAwDgYDVQQLDAdSb290IENBMSowKAYDVQQDDCFU" +
            "V0NBIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwfnK4pAOU5qfe" +
            "CTiRShFAh6d8WWQUe7UREN3+v9XAu1bihSX0NXIP+FPQQeFEAcK0HMMxQhZHhTMidrIKbw/lJVBPhYa+v5guEGcevhEFhgWQxFnQ" +
            "fHgQsIBct+HHK3XLfJ+utdGdIzdjp9xCoi2SBBtQwXu4PhvJVgSLL1KbralW6cH/ralYhzC2gfeXRfwZVzsrb+RH9JlF/h3x+Jej" +
            "iB03HFyP4HYlmlD4oFT/RJB2I9IyxsOrBr/8+7/zrX2SYgJbKdM1o5OaQ2RgXbL6Mv87BK9NQGr5x+PvI/1ry+UPizgN7gr8/g+Y" +
            "nzAx3WxSZfmLgb4i4RxYA7qRG4kHAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRq" +
            "OFsmjd6LWvJPelSDGRjjCDWmujANBgkqhkiG9w0BAQUFAAOCAQEAPNV3PdrfibqHDAhUaiBQkr6wQT25JmSDCi/oQMCXKCeCMErJ" +
            "k/9q56YAf4lCmtYR5VPOL8zy2gXE/uJQxDqGfczafhAJO5I1KlOy/usrBdlsXebQ79NqZp4VKIV66IIArB6nCWlWQtNoURi+VJq/" +
            "REG6Sb4gumlc7rh3zc5sH62Dlhh9DrUUOYTxKOkto557HnpyWoOzeW/vtPzQCqVYT0bf+215WfKEIlKuD8z7fDvnaspHYcN6+NOS" +
            "BB+4IIThNlQWx0DeO4pz3N/GCUzf7Nr/1FNCocnyYh0igzyXxfkZYiesZSLX0zzG5Y6yU8xJzrww/nsOM5D77dIUkR8Hrw==",
        ),
        Root(
            name = "TWCA Global Root CA",
            owner = "台灣網路認證 TWCA",
            group = Group.SERVICE,
            algorithm = "RSA 4096",
            purposes = "財政部電子發票整合服務平台（einvoice.nat.gov.tw）的網站憑證鏈",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "59769007F7685D0FCD50872F9F95D5755A5B2B457D81F3692B610A98672F0E1B",
            b64 = "MIIFQTCCAymgAwIBAgICDL4wDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVFcxEjAQBgNVBAoTCVRBSVdBTi1DQTEQMA4GA1UE" +
            "CxMHUm9vdCBDQTEcMBoGA1UEAxMTVFdDQSBHbG9iYWwgUm9vdCBDQTAeFw0xMjA2MjcwNjI4MzNaFw0zMDEyMzExNTU5NTlaMFEx" +
            "CzAJBgNVBAYTAlRXMRIwEAYDVQQKEwlUQUlXQU4tQ0ExEDAOBgNVBAsTB1Jvb3QgQ0ExHDAaBgNVBAMTE1RXQ0EgR2xvYmFsIFJv" +
            "b3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCwBdvI64zEbooh745NnHEKH1Jw7W2CnJfF10xORUnLQEK1EjRs" +
            "GcJ0pDFfhQKX7EMzClPSnIyOt7h52yvVavKOZsTuKwEHktSz0ALfUPZVr2YOy+BHYC8rMjk1Ujoog/h7FsYYuGLWRyWRzvAZEk2t" +
            "Y/XTP3VfKfChMBwqoJimFb3u/Rk28OKRQ4/6ytYQJ0lM793B8YVwm8rqqFpD/G2Gb3PpN0Wp8DbHzIh1HrtsBv+baz4X7GGqcXzG" +
            "HaL3SekVtTzWoWH1EfcFbx39Eb7QMAfCKbAJTibc46KokWofwpFFiFzlmLhxpRUZyXx1EcxwdE8tmx2RRP1WKKD+u4ZqyPpcC1jc" +
            "xkt2yKsi2XMPpfRaAok/T54igu6idFMqPVMnaR1sjjIsZAAmY2E2TqNGtz99sy2sbZCilaLOz9qC5wc0GZbpuCGqKX6mOL6OKUoh" +
            "Znkfs8O1CWfe1tQHRvMq2uYiN2DLgbYPoA/pyJV/v1WRBXrPPRXAb94JlAGD1zQbzECl8LibZ9WYkTunhHiVJqRaCPgrdLQABDzf" +
            "uBSO6N+pjWxnkjMdwLfS7JLIvgm/LCkFbwJrnu+8vyq8W8BQj0FwcYeyTbcEqYSjMq+u7msXi7Kx/mzhkIyIqJdIzshNy/MGz19q" +
            "CkKxHh53L46g5pIOBvwFItIm4TFRfTLcDwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG" +
            "9w0BAQsFAAOCAgEAXzSBdu+WHdXltdkCY4QWwa6gcFGn90xHNcgL1yg9iXHZqjNB6hQbbCEAwGxCGX6faVsgQt+i0trEfJdLjbDo" +
            "rMjupWkEmQqSpqsnLhpNgb+E1HAerUf+/UqdM+DyucRFCCEK2mlpc3INvjT+lIutwx4116KD7+U4x6WFH6vPNOw/KP4M8VeGTslV" +
            "9xzU2KV9Bnpv1d8Q34FOIWWxtuEXeZVFBs5fzNxGiWNoRI2T9GRwoD2dKAXDOXC4Ynsg/eTb6QihuJ49CcdP+yz4k3ZB3lLg4VfS" +
            "nQO8d57+nile98FRYB/e2guyLXW3Q0iT5/Z5xoRdgFlglPx4mI88k1HtQJAH32RjJMtOcQWh15QaiDLxInQirqWm2BJpTGCjAu4r" +
            "7NRjkgtevi92a6O2JryPA9gK8kxkRr05YuWW6zRjESjMlfGt7+/cgFhI6Uu46mWs6fyAtbXIRfmswZ/ZuepiiI7E8UuDEq3mi4TW" +
            "nsLrgxifarsbJGAzcMzs9zLzXNl5fe+epP7JI8Mk7hWSsT2RTyaGvWZzJBPqpK5jwa19hAM8EHiGG3njxPPyBJUgriOCxLM6AGK/" +
            "5jYk4Ve6xx6QddVfP5VhK8E7zeWzaGHQRiapIVJpLesux+t3zqY6tQMzT3bR51xUAV3LePTJDL/PEo4XLSNolOer/qmyKwbQBM0=",
        ),
        Root(
            name = "USERTrust RSA Certification Authority",
            owner = "Sectigo（USERTrust）",
            group = Group.SERVICE,
            algorithm = "RSA 4096",
            purposes = "內政部移民署（immigration.gov.tw）的網站憑證鏈",
            source = "CCADB（Microsoft、Mozilla 根憑證計畫）",
            sha256 = "E793C9B02FD8AA13E21C31228ACCB08119643B749C898964B1746D46C3D4CBD2",
            b64 = "MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5l" +
            "dyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVT" +
            "RVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkG" +
            "A1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNU" +
            "IE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUA" +
            "A4ICDwAwggIKAoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B3PHTsdZ7NygRK0faOca8Ohm0" +
            "X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkYtJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+" +
            "bJz/Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47" +
            "aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6c0Pl" +
            "fg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmTYo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaD" +
            "zLhn4ugTncxbgtNMs+1b/97lc6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4eeUB9XVKg+/XRj" +
            "L7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeEHg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+C" +
            "DwIDAQABo0IwQDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w" +
            "DQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPFUp/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtO" +
            "uowhT6KOVWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3ATiUFJVDBwn7YKnuHKsSjKCaXqeY" +
            "alltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR" +
            "iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYzeSf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5o" +
            "GzuCr+yDZ4XUmFF0sbmZgIn/f3gZXHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/qS3fuQL3" +
            "9ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRBVXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGw" +
            "sAvgnEzDHNb842m1R0aBL6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfGjjxDah2nGN59PRbx" +
            "YvnKkKj9",
        ),
        )
    }

    val mainlandChina: List<Root> get() = all.filter { it.group == Group.MAINLAND_CHINA }
    val services: List<Root> get() = all.filter { it.group == Group.SERVICE }
}

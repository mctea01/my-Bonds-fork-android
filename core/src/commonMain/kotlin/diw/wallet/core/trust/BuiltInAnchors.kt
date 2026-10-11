package diw.wallet.core.trust

import diw.wallet.core.profile.bonds.TwPkiAnchors
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64

/**
 * X.509 anchors in operation that the wallet trusts without an import: the Taiwan government PKI (GPKI), as published
 * by the Government Root Certification Authority (grca.nat.gov.tw, IssuedToThisCA.p7b of each CA), checked against
 * those files on 2026-10-11. All are valid now; the G2 generation runs until 2033/2034 beside G3.
 *
 * They certify who a party is (an agency, an organisation, a company, a citizen), not that it is a listed issuer of
 * wallet credentials, so a match is T2 (identity verified) rather than T1. Citizen certificates (MOICA) identify
 * individuals: they anchor verifiers (a person checking a document) and document signatures, but never issuers. The medical CA (HCA) is not
 * included: its repository was not reachable when the list was built.
 */
object BuiltInAnchors {
    /** One anchor: its name, the roles it is trusted for, and the certificate. */
    class Anchor(val name: String, val roles: Set<TrustRole>, private val b64: String) {
        val certificate: X509Cert by lazy { X509Cert(ByteString(b64.fromBase64())) }
    }

    const val SOURCE = "https://grca.nat.gov.tw"

    private val ORGANISATION = setOf(TrustRole.ISSUER, TrustRole.STATUS_LIST, TrustRole.VERIFIER, TrustRole.DOCUMENT)
    /** Citizens verify and sign documents; they never issue wallet credentials. */
    private val PERSON = setOf(TrustRole.VERIFIER, TrustRole.DOCUMENT)
    /** GRCA anchors time stamps and, for documents, every GPKI chain that includes its CA certificate. */
    private val ROOT = setOf(TrustRole.TSA, TrustRole.DOCUMENT)

    val all: List<Anchor> by lazy {
        listOf(
            Anchor("GRCA 政府憑證總管理中心", ROOT, GRCA_2002),
            Anchor("GRCA 政府憑證總管理中心（2012）", ROOT, GRCA_2012),
            Anchor("GRCA G3 政府憑證總管理中心", ROOT, TwPkiAnchors.GRCA_G3_B64),
            Anchor("GCA 政府憑證管理中心", ORGANISATION, GCA_G2),
            Anchor("GCA G3 政府憑證管理中心", ORGANISATION, GCA_G3),
            Anchor("XCA 組織及團體憑證管理中心", ORGANISATION, XCA_G2),
            Anchor("XCA G3 組織及團體憑證管理中心", ORGANISATION, XCA_G3),
            Anchor("MOEACA 工商憑證管理中心", ORGANISATION, MOEACA_G2),
            Anchor("MOEACA G3 工商憑證管理中心", ORGANISATION, MOEACA_G3),
            Anchor("MOICA 內政部憑證管理中心（自然人憑證）", PERSON, MOICA_G2),
            Anchor("MOICA G3 內政部憑證管理中心（自然人憑證）", PERSON, TwPkiAnchors.MOICA_G3_B64),
        )
    }

    /** Government Root Certification Authority (2002, until 2032), SHA-256 7600295eefe85b9e1fd624db76062aaaae59818a54d2774cd4c0b2c01131e1b3. */
    private const val GRCA_2002 =
        "MIIFcjCCA1qgAwIBAgIQH51ZWtcvwgZEpYAIaeNe9jANBgkqhkiG9w0BAQUFADA/MQswCQYDVQQGEwJUVzEwMC4GA1UECgwnR292" +
        "ZXJubWVudCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTAyMTIwNTEzMjMzM1oXDTMyMTIwNTEzMjMzM1owPzELMAkG" +
        "A1UEBhMCVFcxMDAuBgNVBAoMJ0dvdmVybm1lbnQgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCAiIwDQYJKoZIhvcNAQEB" +
        "BQADggIPADCCAgoCggIBAJoluOzMonWoe/fOW1mKydGGEghU7Jzy50b2iPN86aXfTEc2pBsBHH8eV4qNw8XRIePaJD9IK/ufLqGU" +
        "5ywck9G/GwGHU5nOp/UKIXZ3/6m3xnOUT0b3EEk3+qhZSV1qgQdW8or5BtD3cCJNtLdBuTK4sfCxw5w/cP1T3YGq2GN49thTbqGs" +
        "aoQkclSGxtKyyhwOeYHWtXBiCAEuTk8O1RGvqa/lmr/czIdtJuTJV6L7lvnM4T9TjGxMfptTCAtsF/tnyMKtsc2AtJfcdgEWFelq" +
        "16TheEfOhtX7MfP6Mb40qij7cEwdScevLJ1tZqa2jWR+tSBqnTuBto9AAGdLiYa4zGX+FVPpBMHWXx1E1wovJ5pGfaENda1UhhXc" +
        "STvxls4Pm6Dso3pdvtUqdULle96ltqqvKKyskKw4t9VoNSZ63Pc78/1Fm9G7Q3hub/FCVGqY8A2tl+lSXunVanLeavcbYBT0peS2" +
        "cWeqH+riTcFCQP5nRhc4L0c/cZyu5SHKYS1tB6iEfC3uUSXxY5Ce/eFXiGvviiNtsea9P63RPZYLhY3Naye7twWb7LuRqQoHEgKX" +
        "TiCQ8P8NHuJBO9NAOueNXdpm5AKwB1KYXA6OM5zCppX7VRluTI6uSw+9wThNXo+EHWbNxWCWtFJaBYmOlXqYwZE8lSOyDvR5tMl8" +
        "wUohAgMBAAGjajBoMB0GA1UdDgQWBBTMzO/MKWCkO7GStjz6MmKPrCUVOzAMBgNVHRMEBTADAQH/MDkGBGcqBwAEMTAvMC0CAQAw" +
        "CQYFKw4DAhoFADAHBgVnKgMAAAQUA5vwIhP/lSg209yewDL7MTqKUWUwDQYJKoZIhvcNAQEFBQADggIBAECASvomyc5eMN1PhnR2" +
        "WPWus4MzeKR6dBcZTulStbngCnRiqmjKeKBMmo4sIy7VahIkv9Ro04rQ2JyftB8M3jh+Vzj8jeJPXgyfqzvS/3WXy6TjZwj/5cAW" +
        "tUgBfen5Cv8b5Wppv3ghqMKnI6mGq3ZW6A4M9hPdKmaKZEk9GhiHkASfQlK3T8v+R0F2Ne//AHY2RTKbxkaFXeIksB7jSJaYV0eU" +
        "VXoPQbFEJPPB/hprv4j9wabak2BegUqZIJxIZhm1AHlUD7gsL0u8qV1bYH+Mh6XgUmMqvtg7hUAV/h62ZT/FS9p+tXo1KaMuephg" +
        "IqP0fSdOLeq0dDzpD6QzDxARvBMB1uUO07+1EqLhRSPAzAhuYbeJq4PjJB7mXQfnHyA+z2fI56wwbSdLaG5LKlwCCDTb+HbkZ6Mm" +
        "nD+iMsJKxYEYMRBWqoTvLQr/uB930r+lWKBi5NdLkXWNiYCYfm3LU05er/ayl4WXudpVBrkk7tfGOB5jGxI7leFYrPLfhNVfmS8N" +
        "VVvmONsuP3LpSIXLuykTjx44VbnzssQwmSNOXfJIoRIM3BKQCZBUkQM8R+XVyWXgt0t97EfTsws+rZ7QdAAO671RrcDeLMDDav7v" +
        "3Aun+kbfYNucpllQdSNpc5Oy+fwC00fmcc4QAu4njIT/rEUNE1yDMuAlpYYsfPQS"

    /** Government Root Certification Authority (2012, until 2037), SHA-256 70b922bfda0e3f4a342e4ee22d579ae598d071cc5ec9c30f123680340388aea5. */
    private const val GRCA_2012 =
        "MIIFSzCCAzOgAwIBAgIRALZLiAfiI+7IXBKtpg4GofIwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVFcxMDAuBgNVBAoMJ0dv" +
        "dmVybm1lbnQgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xMjA5MjgwODU4NTFaFw0zNzEyMzExNTU5NTlaMD8xCzAJ" +
        "BgNVBAYTAlRXMTAwLgYDVQQKDCdHb3Zlcm5tZW50IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEB" +
        "AQUAA4ICDwAwggIKAoICAQC2/5c8gb4BWCQnr44BK9ZykjAyG1+bfNTUf+ihYHMwVxAA+lCWJP5Q5ow6ldFXeYTVZ1MMKoI+GFy4" +
        "MCYa1l7GLbIEUQ7v3wxjR+vEEghRK5lxXtVpe+FdyXcdIOxWjuVhYC386RyA3/pqg7sFtR4jEpyCygrzFB0g5AaPQySZn7YKk1pz" +
        "GxY5vgW28YylZJKPBeRcdvc5w88tvQ7Yy6gOMZvJRg9nU0MEj8iyyIOAX7ryD6uBNaIgIZfOD4k0eA/PH07p+4woPN405+2f0mb1" +
        "xcoxeNLOUNFggmOd4Ez3B66DNJ1JSUPUfr0t4urHcWWACOQ2nnlwCjyHKenkkpTqBpIpJ3jmrdc96QoLXvTg1oadLXLLi2RW5vSu" +
        "eKWgOTNYPNyoj420ai39iHPplVBzBN8RiD5C1gJ0+yzEb7xs1uCAb9GGpTJXA9ZN9E4KmSJ2fkpAgvjJ5E7LUy3Hsbbi08J1J265" +
        "DnGyNPy/HE7CPfg26QrMWJqhGIZO4uGqs3NZbl6dtMIIr69c/aQCb/+4DbvVq9dunxpPkUDwH0ZVbaCSw4nNt7H/HLPLo5wK4/7N" +
        "qrwB7N1UypHdTxOHpPaY7/1J1lcqPKZc9mA3v9g+fk5oKiMyOr5u5CI9ByTPisubXVGzMNJxbc5Gim18SjNE2hIvNkvy6fFRCW3b" +
        "apcOFwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTVZx3gnHosnMvFmOcdByYqhux0zTAOBgNVHQ8BAf8EBAMC" +
        "AQYwDQYJKoZIhvcNAQELBQADggIBAJA75cJTQijq9TFOjj2Rnk0J89ixUuZPrAwxIbvx6pnMg/y2KOTshAcOD06Xu29oRo8OURWV" +
        "+Do7H1+CDgxxDryRT64zLiNB9CZrTxOH+nj2LsIPkQWXqmrBap+8hJ4IKifd2ocXhuGzyl3tOKkpboTeRmv8JxlQpRJ6jH1i/Nrn" +
        "zLyfSa8GuCcn8on3Fj0Y5r3e9YwSkZ/jBI3+BxQaWqw5ghvxOBnhY+OvbLamURfr+kvriyL2l/4QOl+UoEtTcT9a4RD4co+WgN2N" +
        "ApgAYT2NvC2xR8zaXeEgp4wxXPHj2rkKhkfIoT0Hozymc26Uke1uJDr5yTDRB6iBfSZ9fYTfhsmL5a4NHr6JSFEVg5iWL0rrczTX" +
        "dM3Jb9DCuiv2mv6Z3WAUjhv5nDk8f0OJU+jlwqu+Iq0nOJt3KLejY2OngeepaUXrjnhWzAWEx/uttjB8YwWfLYwkf0uLkvw4Hp+g" +
        "pVezbp3YZLhwmmBScMip0P/GnO0QYV7Ngw5u6E0CQUridgR51lQ/ipgyFKDdLZznuoJxo4ZVKZnSKdt1OvfbQ/+2W/u3fjWAjg1s" +
        "rnm3Ni2XUqGwB5wH5Ss2zQOXlL0tDjQG/MAWifw3VOTWzz0TBPKR2ck2Lj7FWtClTILD/y58Jnb38/1FoqVuVa4uzM8siTTa9g3n" +
        "kagQ6hed8vbs"

    /** 政府憑證管理中心（GCA, until 2033）, SHA-256 1f992b635905fc0eecedaabceaf9741d77778dd838de92b5bb5111722f4631d6. */
    private const val GCA_G2 =
        "MIIFLzCCAxegAwIBAgIQMe5Y77XBpI+a7fR13bilwTANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJUVzEwMC4GA1UECgwnR292" +
        "ZXJubWVudCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTEzMDEzMTAzMjIzNFoXDTMzMDEzMTAzMjIzNFowRDELMAkG" +
        "A1UEBhMCVFcxEjAQBgNVBAoMCeihjOaUv+mZojEhMB8GA1UECwwY5pS/5bqc5oaR6K2J566h55CG5Lit5b+DMIIBIjANBgkqhkiG" +
        "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtX7xPZUtp5iBGQvqYghJUoLeyCJJoaTcc1bcOGHij64WUBYpDu8KKEQKR1y3zjcDXrLcZX48" +
        "3tmNs92DXSNuBHlx+we1aFyuLpKQVCji97ys3KeMxAEcaXqo3cZu8nY3g//zkvX80G4RoCyDR86Z420R3mb0GlVw/9TEK8+oduZq" +
        "AArEdfionpbEK5zZ/8qaaHafgqMBQGuzfccDKLoWRcTzu3S0IvOpVU6pcB0rJOtc4F7c16tQdXfoa8sjfcveKKbUQF6AklwugRuf" +
        "HdLqEVpOiGRcDPaHtT6SHJ7D/t+A/rAXMPidcksQrea/E+5+lehqEMHSA/gSLa9Ph+/gDQIDAQABo4IBIDCCARwwHwYDVR0jBBgw" +
        "FoAU1Wcd4Jx6LJzLxZjnHQcmKobsdM0wHQYDVR0OBBYEFNEYZ8NX/hKakWtfXzHqPsKEh/u9MA4GA1UdDwEB/wQEAwIBBjA+BgNV" +
        "HR8ENzA1MDOgMaAvhi1odHRwOi8vZ3JjYS5uYXQuZ292LnR3L3JlcG9zaXRvcnkvQ1JMMi9DQS5jcmwwVgYIKwYBBQUHAQEESjBI" +
        "MEYGCCsGAQUFBzAChjpodHRwOi8vZ3JjYS5uYXQuZ292LnR3L3JlcG9zaXRvcnkvQ2VydHMvSXNzdWVkVG9UaGlzQ0EucDdiMBIG" +
        "A1UdEwEB/wQIMAYBAf8CAQAwHgYDVR0gBBcwFTAJBgdghnZlAAMDMAgGBmeBDAECAjANBgkqhkiG9w0BAQsFAAOCAgEAs3KvqDSI" +
        "q6GERR/SonDfYnrpF/IdZLM9gBfsIIafNeeWjFCIuC5Ah7LEIhZYPP/D8y00OCRlZ7GoY4JZIvTFA1fb2umEmKC/ssCwQdUxyd52" +
        "JfbqBL5N0cP2eU1x1ZG8d1z8uIq7ItyfO5ML1eAboYMHsO7c10pLmtufZj8VZ4zp4DTRxVzROPKwlIbRQSKNlymWgAop+Eg9b40l" +
        "fBMBxFppb3R4IZpijCpy0RbPOzvtmDpen3WZmJ+vsCqc08b8JqDeRG5zQI1sIeV15qqGZuV8oL5gFi4niltkLNS3fGYAr4+LXVoj" +
        "MWIO/NoeJi+i3AtfhnN/w3Ixzhxi39pN+hYzFGtsZNioUC2MQexFJS+AQ4s8D41cRCMwovfi0erTbWKhTPoQXirUDV/ZSUjUlLDb" +
        "XzdiUB+mxWd2k16HYcvMFUevxbNzJAxP355Tq9tliZpM/7MVq0/Bw4SGxxQRQF1uVQjMBtEsRYHKVZ1IBBJVOe8jZhc81Sw3jDmm" +
        "Ttyjx1o2m8VVImsiIP2iPI3hlw/UCwCGRg5xvqqW72w2niT9pXdvZowBVbhP24wtumuA45M5h4UNZRNo4/NG3UwS9eLKtfB06YFf" +
        "3DcBban/Drf8LX8OGvF++Im3SeGJ6zhUlYOVJcTHpR6TToXoKzvuzegRL2vQ4k22B++JtOQgsAg="

    /** 政府憑證管理中心 - G3（until 2042）, SHA-256 723fb2e74b0ff46a79640bc9c065d08fc62c5044e6cc855316fc74e14545c4a5. */
    private const val GCA_G3 =
        "MIIGajCCBFKgAwIBAgIRANihslJZ4Numk5pLcvKuQaIwDQYJKoZIhvcNAQELBQAwWDELMAkGA1UEBhMCVFcxEjAQBgNVBAoMCeih" +
        "jOaUv+mZojE1MDMGA1UEAwwsR292ZXJubWVudCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzMwHhcNMjIwNjA3MDMw" +
        "NzE0WhcNNDIwNjA3MTU1OTU5WjBJMQswCQYDVQQGEwJUVzESMBAGA1UECgwJ6KGM5pS/6ZmiMSYwJAYDVQQDDB3mlL/lupzmhpHo" +
        "rYnnrqHnkIbkuK3lv4MgLSBHMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALMbyTROOXM9HCYlLMLoGsxd8b7fbS6u" +
        "lH/482zJIWTaQ+toRwEG8AALiH/lNE1RfmVW3kmMd6hI5nUfjmbb9zf+r33Q/2l8LGBIH0MeJMBHXr0C/PQxAEtzhFn3QDJMyfzx" +
        "tOI8hAeTN9fAysxdFHZckcc/yGWUwr4d9r2XOp7NJPIEMFXsGzr/aKPbiJEZOdKzkSSbOnq0ijJgc1+q+EYKKwZ5xWgjWh7Bz8xI" +
        "LKgE9lvFmj65aF/uH/HEcEPhaXXABr/TCOJLyrKJ+qRQNOBmHOVSEV5YE+4c8VWPD9Mq+CAeTQ8GVC19hSJXloFqwvKC/1N3YK8K" +
        "5MmaPX5sz2lK8lSeIedYWRf/3GPbRrMhy7XNA+7CKQYhna0YRAmLQJqrMLnMGLKFLZi6sGc9IGUyPaX5pH3v2jicTNjPo+WTChY5" +
        "YXRxU6QDRYg7cm0Ou67F4nbQxGRPdO8YUYUkeCyHHPBxfXLTRghskuhy88989z0EaTnzGSOHpkYniVIIm/+lNryoCd6QucfMXY9u" +
        "qN/OIlnFpWQjuMrQrjmAqjG1Dcfz9Q+jPEUygp8r6VKEFcNVqKnJvD/NT/BpbjydUL8wBajp0yCSoVuKmJk7NdJBBHqiOXQEY5d9" +
        "jF1lvMTLeaefVPd7XFBa5hrnmu2XpAfWsEVAkTMcTKUhf95ANB6bAgMBAAGjggE8MIIBODAfBgNVHSMEGDAWgBQ6kI7nQUcZc9yc" +
        "vaN+2D0+gwkfAzAdBgNVHQ4EFgQUD/vWuMskS0g3p80y3tukkGEgrrwwDgYDVR0PAQH/BAQDAgGGMD4GA1UdHwQ3MDUwM6AxoC+G" +
        "LWh0dHA6Ly9ncmNhLm5hdC5nb3YudHcvcmVwb3NpdG9yeS9DUkwzL0NBLmNybDB8BggrBgEFBQcBAQRwMG4wPgYIKwYBBQUHMAKG" +
        "Mmh0dHA6Ly9ncmNhLm5hdC5nb3YudHcvcmVwb3NpdG9yeS9DZXJ0cy9HUkNBRzMuY3J0MCwGCCsGAQUFBzABhiBodHRwOi8vb2Nz" +
        "cC5ncmNhLm5hdC5nb3YudHcvT0NTUDASBgNVHRMBAf8ECDAGAQH/AgEAMBQGA1UdIAQNMAswCQYHYIZ2ZQADAzANBgkqhkiG9w0B" +
        "AQsFAAOCAgEASFPAouzRMDf0zdPg1GvWszZmng5TDu+2GD+zSpYVsvG9jOZOR0EWJcy6gH95rOzayxTC3TAeX6OyrVc76Pyhae2B" +
        "Y/9YlFI/10nUjdBScDlywHXc6uAnbPJkuSPlrRXHSifzwEAgV2bNsRQYx76deVlo5cPfSKihvP6t2XQgUoIIu/akPDEZsiXtqiEC" +
        "Rz/QY2ums7Vz+1GiILR6sOlRF2BbL70DZ6KrSRONoKwKiOZdgCuKb+QuZUZop0JZrsiMOXGoL0cmNhc/WiVwJ34YtPSbaH/fBQdT" +
        "SPwIizZjefPIsBifGfg52bT6ubMn6HOzaeWQHwKnSQ2RjnRBxO8Wf6isYtsMoe5oUFV7ftNX8A49fRMxLGAoS6lvJqC4eALphNMi" +
        "ZxcQ+Qsj/DWtkRPwKUT2IrT1Z6Jftxnoo0kmHm4SPtJrHJSDotkAc8vi67Q2nFCy7lSA1gfi/vDFLrivRq3v9UfWmrpw+SRJgWaN" +
        "xUcy6CiLfFmncH7d1zDimZrIv7gRUUM3bIBngJ5y+gHpGN/4h/fmvnvmIiW3QfcKyc9MrFgtowLvLg992B9ZFX3CYJr3+3h+DD2d" +
        "EzKbbQIrg39rhsEWh9Gfgc/p8N/gxPc8ZaNRvLMewKo2xJHh+9xi7ydlT7Zth929PN7BXAoLPA1g/Rkg2o42MPvzBmPLtw8="

    /** 組織及團體憑證管理中心（XCA, until 2034）, SHA-256 b2ee26fd0be0f80cc2473785cf9e98905a73630e8dabf12aeb968bb4d81a2dd6. */
    private const val XCA_G2 =
        "MIIFLzCCAxegAwIBAgIRAMKlrFEEAdOQ9CYANl+KhjwwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVFcxMDAuBgNVBAoMJ0dv" +
        "dmVybm1lbnQgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNDAxMDIwNjM3MzZaFw0zNDAxMDIwNjM3MzZaME0xCzAJ" +
        "BgNVBAYTAlRXMRIwEAYDVQQKDAnooYzmlL/pmaIxKjAoBgNVBAsMIee1hOe5lOWPiuWcmOmrlOaGkeitieeuoeeQhuS4reW/gzCC" +
        "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWDUhajOvh7cD6hCtT7SsToSJqvu8uYIqa1Rnsmia5DTnRQGbEUubgLdyGz" +
        "fJZWAH7FUPF+9mePUcQPUSUOGvarSsPY+sPiM8ZHxlxAIF6W8QmjKVMYunN9iu74nArzwSXiismSMmlP7Gw7xRXMixwaU3iZ5b0o" +
        "hYyarHoSYnUHMdskZZxejni0Vu9E2EDvx0ntN+l1XUTK4pXxyltIjNM0mz/aXcQKhWU28XMNGngeboN9zGYyeC+s6XQ4oFsxud+B" +
        "OySb5p0mPhfQBhK8jHBZMXh1Vs5/pYiqvrA5ItGue4VOHaUt8qemG78o+9Fsbhf9GztVKPXwD0IoFkj0/TMCAwEAAaOCARYwggES" +
        "MB8GA1UdIwQYMBaAFNVnHeCceiycy8WY5x0HJiqG7HTNMB0GA1UdDgQWBBRb7hVqSRccaoBN6F7nRar/gMegQDAOBgNVHQ8BAf8E" +
        "BAMCAQYwFAYDVR0gBA0wCzAJBgdghnZlAAMDMBIGA1UdEwEB/wQIMAYBAf8CAQAwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cDovL2dy" +
        "Y2EubmF0Lmdvdi50dy9yZXBvc2l0b3J5L0NSTDIvQ0EuY3JsMFYGCCsGAQUFBwEBBEowSDBGBggrBgEFBQcwAoY6aHR0cDovL2dy" +
        "Y2EubmF0Lmdvdi50dy9yZXBvc2l0b3J5L0NlcnRzL0lzc3VlZFRvVGhpc0NBLnA3YjANBgkqhkiG9w0BAQsFAAOCAgEANa6mXvCW" +
        "grZ5S//mvAPB1VeLx7tffT985D08Bdb4QIZ6JRlk3TbzEKJAQXdVTScAarfHLRLcwJDIkBiba1ZuPOnA0HgItDt/xpRc+jeFiWrM" +
        "lF12JbUHsPL7LeKOscH2geTgG203uaObL4p7io1VBkjAVayD1APGzblGJ7SGKcew1J/LuH3MlIwcGVwxhbfrliah6spzwJJ2AwZy" +
        "M1lpjIDDTf/Jhij1dLZbXtc2Go1sZQkN3wx+Y1v3pkdIzTIG4WGCvZci8+vv5BnthnonjwOgHfNXdoZSREggpyz1SR4F4jrt3tvu" +
        "83mHLCuXj/mlSUUiAqAg9zMfawTqNQIP2zfUhBK3PjAwayuwURhkvw8lOyn9lQGHdxwURwT7hXGTdYO1gqECaSI9sMT7ZdSV0JuW" +
        "HV0WivkynNIemn+nSrLugoqTkrlx/9+1xsjutCoXWR7NTW+ekq27HmDdku+IC8dzTwa+rP2el/NAdZA+BHjn0LdrXbXEtrCldSSG" +
        "ioT7iynKbOtNxvXkug5oaPa8xIGs2XC9Sx0AUlzK+k+3SHEv2/jWdlMDw9VHhDKAhQ4v8bWNJ2nQI/eRLgxei+7AWpy8jxeLzN4g" +
        "mff1qw3PEvWkpdENu8fqgE06rhB5CJn1Abcen5X7khuHZ98cmb8hAxM4cbzFNWm3lYqeXBMd9I0="

    /** 組織及團體憑證管理中心 - G3（until 2042）, SHA-256 a07c17472ed382c517da0439cd2d8a567c48f86aeffc8a0bebd6f3a1a54b8ab2. */
    private const val XCA_G3 =
        "MIIGcjCCBFqgAwIBAgIQDuIAulTspM4qwbiwdLRozDANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJUVzESMBAGA1UECgwJ6KGM" +
        "5pS/6ZmiMTUwMwYDVQQDDCxHb3Zlcm5tZW50IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMzAeFw0yMjA2MDcwMzEz" +
        "NTZaFw00MjA2MDcxNTU5NTlaMFIxCzAJBgNVBAYTAlRXMRIwEAYDVQQKDAnooYzmlL/pmaIxLzAtBgNVBAMMJue1hOe5lOWPiuWc" +
        "mOmrlOaGkeitieeuoeeQhuS4reW/gyAtIEczMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiP7GXinqof8gmqb6zjUd" +
        "cfeSVyUZmrXi9UBdRRFLbjcwdFVXWJnyEqvNy/OvzYLYVpgveWgZNItQbCRzM37ZM+CzP0ReXZ8MEdvL8K7cjO9YwbuM4TdV8o+G" +
        "fVP1f6qNC3knGoX2ZtOvc+tV+jbDGcUMkR7qpa9HJhqPvMwRAivoJyQ5WQS6JNGKLv2jKniEseD9LDNMOeNCi3TCO1Emc4CJAaOn" +
        "DCFPVK7UeaiGOex44Fb2h3wI11JfrwIcE6pSWkKO36eILBdIMQpdACVOLBLVMvrBnEB/enMGqg5lP3kzJZw70DtxJdjQLkGHPICC" +
        "vYxrFz+7f1ygMVKAPFjyeXOMT8SU8eNIwZrEbcQbPDWBR1MjlmWGHdrHsppZDNut1r+F3fCUkasDzpXlp/E0Grzs8GyeaLk0vUkM" +
        "GCFT7OlvUdIy28kJaIyDuBU6Zti/H3zjqcgz9XZvm9ZQfYLIV1dcBbG/Bd0BMLv75YMZsixecjLp1WvrH6/tO9us/K88DiVi/pB0" +
        "SsVHgLOaUhYsBAgSnZK1b6eA7l/504QnxAa6ydcqCFEBRPvKZ8XQgyXJ1AL2vkzg9DMH0LJkcmZx21VmOTSSTsg/ORKGENTJleid" +
        "nglunRgF/kDehLKfkJt72Xe4Swt+mB7V8gxHvoHICh9CayGN/gkIy5/UR3CADGMCAwEAAaOCATwwggE4MB8GA1UdIwQYMBaAFDqQ" +
        "judBRxlz3Jy9o37YPT6DCR8DMB0GA1UdDgQWBBTYnbm5CElH3wPA9NrKM81Fb6tf2DAOBgNVHQ8BAf8EBAMCAYYwPgYDVR0fBDcw" +
        "NTAzoDGgL4YtaHR0cDovL2dyY2EubmF0Lmdvdi50dy9yZXBvc2l0b3J5L0NSTDMvQ0EuY3JsMHwGCCsGAQUFBwEBBHAwbjA+Bggr" +
        "BgEFBQcwAoYyaHR0cDovL2dyY2EubmF0Lmdvdi50dy9yZXBvc2l0b3J5L0NlcnRzL0dSQ0FHMy5jcnQwLAYIKwYBBQUHMAGGIGh0" +
        "dHA6Ly9vY3NwLmdyY2EubmF0Lmdvdi50dy9PQ1NQMBIGA1UdEwEB/wQIMAYBAf8CAQAwFAYDVR0gBA0wCzAJBgdghnZlAAMDMA0G" +
        "CSqGSIb3DQEBCwUAA4ICAQCF++ggPPrSdFeIs7smES6hvu4FALxLLXGGD90tYe9fbm8IiR+7WsNSezS1ep6hCCUXX64DDquave8x" +
        "KZ84weYNUwWwSmI4nq4l3GYz5hAz/BkamtsA866Rfnck9FItDT82qv/3qMAY3FI2xWraAOiA1wARqjMr7Eenz1bko5AWJkTEk6dK" +
        "/lJLjJN2zhY9ikPAjFTaimyAcvrb9+xf737k5hDjGwYhmY+g+4hqjFtSEtA6rOGnGpTcRTtMpSfgGGtveyKi7h5cACxQ+cVQMjvy" +
        "AkS2NDPcXAvxCaKVNcuoU6jzC6Pd9WuuNOaejATvbrMqABS+WXperEN1eQUGRCa5TqOTYWtRYIPLnv3y28DYS8S6oTDTu+Ya182e" +
        "ANLXa9NDEt/g/9gQxMYKMu4JllbZtKP7VJS0AHqn49RtU69yvSlod0yLmAscra4BOf5fJu0VuF8SPeNqWVsf4bWInf+qVEQOeago" +
        "x4J5BXPfFXSrGPp12/M1xhqoiWzTEs9A3bj0h38yd5PLDfwDru68dusRhwZQr/xtNn3NxeMNvgNBMZ2dy+nzi+xCwHlo3+ts9MvP" +
        "fXh5w3CxPiro3iiJTrc8T3oA4+ed8s7211GLj8iOTUpJt4JRN7cQEjTd4VWWc83f3KlUxyxyF1wbZZ0EqfywNztMgrRIPgKUKth6" +
        "d5vUTQ=="

    /** 工商憑證管理中心（MOEACA, until 2033）, SHA-256 0cf08b01e554eb7631d4916e9e8c5398af994242a26ca388638622a0e59ff379. */
    private const val MOEACA_G2 =
        "MIIFJjCCAw6gAwIBAgIRAIcpzVz5C/q2EtJsL59ntt0wDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVFcxMDAuBgNVBAoMJ0dv" +
        "dmVybm1lbnQgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xMzAxMzEwMzI5MjBaFw0zMzAxMzEwMzI5MjBaMEQxCzAJ" +
        "BgNVBAYTAlRXMRIwEAYDVQQKDAnooYzmlL/pmaIxITAfBgNVBAsMGOW3peWVhuaGkeitieeuoeeQhuS4reW/gzCCASIwDQYJKoZI" +
        "hvcNAQEBBQADggEPADCCAQoCggEBAMG3WIQYAAdtj+AhfKmw5DkyxPPgNDhdRWSi7eFdteLUuD6yRn6EQtNm9OfcSpPhiZdBsWFZ" +
        "/ygBWJs+ur6Z0MZJiPBD5tN8GcSkqfVVymJ1pcJRow5bCS5olKQOpEyoOKj3UR+piZeqFfXnOIdW0mAEsa9Oc4RSgNQUupsHRhBi" +
        "U3TjFbOLg2A+7qbHdCTqwX0akIPKGIuZf16z8CdSj4kFHY2pjZC3lDLvPLEOQWNUCz2fM+vrhqySmGDr8ASA1J4lM8fYKEg8vCjv" +
        "LNtCmJRNcN9JIlLbpp73Tsk0qSKsFh7oacF3A/OAlQtH+ErG5VxUqfv5YG7qDYOesG04mj8CAwEAAaOCARYwggESMB8GA1UdIwQY" +
        "MBaAFNVnHeCceiycy8WY5x0HJiqG7HTNMB0GA1UdDgQWBBSZRHoCcuttZSKzAleP1qHdOgIPbDAOBgNVHQ8BAf8EBAMCAQYwFAYD" +
        "VR0gBA0wCzAJBgdghnZlAAMDMBIGA1UdEwEB/wQIMAYBAf8CAQAwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cDovL2dyY2EubmF0Lmdv" +
        "di50dy9yZXBvc2l0b3J5L0NSTDIvQ0EuY3JsMFYGCCsGAQUFBwEBBEowSDBGBggrBgEFBQcwAoY6aHR0cDovL2dyY2EubmF0Lmdv" +
        "di50dy9yZXBvc2l0b3J5L0NlcnRzL0lzc3VlZFRvVGhpc0NBLnA3YjANBgkqhkiG9w0BAQsFAAOCAgEACENJwFaEgZuuyyGV0xSN" +
        "luUGzebk/9izfXUwIB8hi3/7RRn1BG4Fob/hRENOxmPahc88MWj49mpopDrB30Fmps7KEkZ1sdiCmd7z2b4hndBqW7Zmmt5iS8DI" +
        "XPpOAl2b4ZPxi4CYdz4No4donzd22Yyeg+UxIZfr7VPKWdpqjpmCvTc37Ozy0ZXt81U5Xqu335+N3IBjV4YYonbaAEiDcUFBmbFn" +
        "IGYPQ4hbyqizA/t/7H60XtLlJLv5toEfixFYmhztfU7kxyOe7Hjd4dDRIngX/CZ02UKs1Es590SZKRkrxQDzoGLWoG8MEYrcoFQk" +
        "NSVqFGHrXjCASb37H9d7FGYCG93FQzsqq389lqHN6rrBAKkwuv5MoSFLzPCmLtQx2C8GUwfQnsoec5ykGnhAKywmqJLRKmk+362l" +
        "x91VpgKxiDso4dcRTnpke7bqw2lcFhGkEbZ0QDcbc9MgH6GffUnwDIqd8lpocIsldC8GsY+t3IZQl0mcdu6pCDlBTkbb5PB3lelt" +
        "PiIAZVuJlthltzGnu1qB87s9lctPVw4Bc1R0F2y6A0F8bSgZKYjQHrydvHZdIoUzEh5ZglQNT/ugEOqxuxwMI3wr9jDTQ06pqxof" +
        "K07R63MYsRHXSmZMt79OgpsTrnK/A/oqjVOZMDAzK9FzjPuHDExcth4V+B2P+sg="

    /** 工商憑證管理中心 G3（until 2042）, SHA-256 b144fa2c7041b093a6775f557f1707499750ff7aedb0510dd573dd46a98a0d6c. */
    private const val MOEACA_G3 =
        "MIIGZDCCBEygAwIBAgIQdKpG5Eq4iNOosKDJe2230TANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJUVzESMBAGA1UECgwJ6KGM" +
        "5pS/6ZmiMTUwMwYDVQQDDCxHb3Zlcm5tZW50IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMzAeFw0yMjA2MDcwMzIw" +
        "MDBaFw00MjA2MDcxNTU5NTlaMEQxCzAJBgNVBAYTAlRXMRIwEAYDVQQKDAnooYzmlL/pmaIxITAfBgNVBAsMGOW3peWVhuaGkeit" +
        "ieeuoeeQhuS4reW/gzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJwh/gGnalJhrq4QAu/h4UrjKjorW+q9T7RbvraK" +
        "ZucK5zqbqO6Xhz8WHegacR5WUyB9aZydH9dN+gzTeXB4Mts4xN4zMEHgj7nFoVJWZCCO/MxGhl6j+V0p40jlUX9XDuYMr0pL+WbO" +
        "bPpMm+Ap3Oy1EM0ZG6fH5MwUq4CtRBgOuMHlSSd/GgiJ7i8ShYdxeFWWCbpIb4f4dF5RAGDxQIEUXw4wBUsiJ3F16qfdD1uMGAFO" +
        "9ZI8QvbYafeIZ4hj9hwjC+WqWUeCAE/HIWIhjdRXzedt2sozOkUDFQwUPSwu840RDsavZpHZsTd2ep0hBJiCtWgvVzDblfRN+3mu" +
        "pLDZE0glkzpm2OXQOWjCz2URHCAsCq3Xj4kuk0MXRw1Znhz5FwEzLqY2PXQELBxYNmNi5RAWnFA8Inq2ZEGkrfzNK5u7pBwm4Hmr" +
        "sxXqf6DGZlH59CUNQ+gXtab98rMXkByKnoEn+cP7NI9KTHTr7VHfL2ess5XbhRhQam5TIP+sjEDR5J2q7XauCPesD6Xh/g78Sxi7" +
        "dQnohKjuL4ONIUe+0EQDfH3B16+/e1C8XTVh/Fpye0g2ziSlglIp6+2Td63melF8JRZ6kXaEKi9kTvpN97ATq2JalBjDynBVzA7W" +
        "5fzUyKU9P3pAAdlKpCXW6J4kg8tqxDlMrhPCSDrn426lAgMBAAGjggE8MIIBODAfBgNVHSMEGDAWgBQ6kI7nQUcZc9ycvaN+2D0+" +
        "gwkfAzAdBgNVHQ4EFgQURsxZ+GZ8c2pwS4/z1hgT5iDenGgwDgYDVR0PAQH/BAQDAgGGMD4GA1UdHwQ3MDUwM6AxoC+GLWh0dHA6" +
        "Ly9ncmNhLm5hdC5nb3YudHcvcmVwb3NpdG9yeS9DUkwzL0NBLmNybDB8BggrBgEFBQcBAQRwMG4wPgYIKwYBBQUHMAKGMmh0dHA6" +
        "Ly9ncmNhLm5hdC5nb3YudHcvcmVwb3NpdG9yeS9DZXJ0cy9HUkNBRzMuY3J0MCwGCCsGAQUFBzABhiBodHRwOi8vb2NzcC5ncmNh" +
        "Lm5hdC5nb3YudHcvT0NTUDASBgNVHRMBAf8ECDAGAQH/AgEAMBQGA1UdIAQNMAswCQYHYIZ2ZQADAzANBgkqhkiG9w0BAQsFAAOC" +
        "AgEAO2OLpnbVNF4kkhjAffZT9AgPBHuNWSg0N+qYkFmSZhRk5/fiMnOmqITjjKDJ4YAu9gDxPOB0p+OZz3ODK2GLvJm4XEisdN3Z" +
        "oGsprlkLpek+MTuj0ka61ZKhWYqyBOIBzPFsTxSZ8dBSKRkGDpXn4PdM8KdnYqZTDc02n75rz36fTIeV1AOBtfdC1aj3nyt+QIsP" +
        "cRa22z6YbxzZncDytDfhJg93jxH7tathibqu65wbh/0DHyP3hE86PzzMX/sFiR+97BwtQbxzl8PgPpIzOROER16FViGdlggoQxPP" +
        "2E4LkGNIvoc2Iw8uWKBi3f2KY9CmdTZ9q+Z/qIasRvRoAOp17diXNkdSTNcpP8hcuWKJSFdetM27cGKHrguzDGSVBz5oabtwTJQ/" +
        "UtnbQ2j6t+uX8reSPnvgSfxiW1lLU3w/S4gyoMczpYd5CZS033h57k/6HjciiaXT9g6+325P+OhM9uVdYPwW4W0glBDPkPxI2PMR" +
        "EAoy4XKGdozDJJsYXHj2fO47GOjBtNYx/D7AhUm6QL/EXpDLeNao+dCjkOCnRKzhMseuLq2xKzPIFH0jaz5DG9mSlmIfbAdWOLm5" +
        "DrViy7jIamHUibvwPSBDxc5bDw6Tugeqy5GlmBQUPrYI6Jr/VcCtC09MKEWbg7ZxuKZ392Y8EgqUf9awH156W1U="

    /** 內政部憑證管理中心（MOICA, until 2034）, SHA-256 c4c462de463f856804dc898338d2cecb55fba74155851599d8fb7d70218fd1be. */
    private const val MOICA_G2 =
        "MIIFKDCCAxCgAwIBAgIQUcO1wamhWIYJIiIx1hrArTANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJUVzEwMC4GA1UECgwnR292" +
        "ZXJubWVudCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE0MDEwMjA2MzEwNFoXDTM0MDEwMjA2MzEwNFowRzELMAkG" +
        "A1UEBhMCVFcxEjAQBgNVBAoMCeihjOaUv+mZojEkMCIGA1UECwwb5YWn5pS/6YOo5oaR6K2J566h55CG5Lit5b+DMIIBIjANBgkq" +
        "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn9gInAVVnWPVqzS8XfaF+10vRLo3ulZAI4sAYxrOcFCTNQnQ+bZzb/6iqWgg4fvAxbIb" +
        "MZfhbQ01eihjledeZEAvN66P/87iSBwiplWESeE1LrKEQkot4ic2F/YKXU9/u2Vk8ek6pQzoxNMNg5BACTYqAWC13VPoGPiPNErx" +
        "Lphj5VJopMgboiCUETh1UYy/TVAZUIHWMKpALi+eqThHJc+oJ1Qju0C715zdnRI3HQYkuFoF9vYiOSLJgVUeqJ538E3z4iuTUZ+j" +
        "cohxfSFGt4e3hwPVqn/xhn+cYI8gbpxqOfAMLyv/+REKhb8Vwl2uILOKf29aEgJtCKHLxoEpHQIDAQABo4IBFjCCARIwHwYDVR0j" +
        "BBgwFoAU1Wcd4Jx6LJzLxZjnHQcmKobsdM0wHQYDVR0OBBYEFPqbNGcJCpgi92JIi4ImpkXFwyKkMA4GA1UdDwEB/wQEAwIBBjAU" +
        "BgNVHSAEDTALMAkGB2CGdmUAAwMwEgYDVR0TAQH/BAgwBgEB/wIBADA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vZ3JjYS5uYXQu" +
        "Z292LnR3L3JlcG9zaXRvcnkvQ1JMMi9DQS5jcmwwVgYIKwYBBQUHAQEESjBIMEYGCCsGAQUFBzAChjpodHRwOi8vZ3JjYS5uYXQu" +
        "Z292LnR3L3JlcG9zaXRvcnkvQ2VydHMvSXNzdWVkVG9UaGlzQ0EucDdiMA0GCSqGSIb3DQEBCwUAA4ICAQAYjLOx0ErTqE8Yul0W" +
        "IRw7yl7UPy23z1xNn2lhs022lpTSWA8ebx3fATUnSPx6oBiGoxG8U/x+NV5DgUy7qenxXHscgOVZVpf7avGcrq8FYrZ0nRGmMCRC" +
        "30lELnrrH7C9H8YTVZymh2Ovg2jtJHupvmvb43AV9T68T/739lmSkaw7/tu+Ea3Wtxlunzw++5ameC/UZ/1LN0qt/ImKlxBIhXmJ" +
        "bhrHGl20bQp3ZfvGtQ8n03rJtX6dbN2U+JQO4LMcY/3T6Q1sPy2KLA0f2sW4oUM13g8UCIQvhV029DKL3rkDL9xzUHfKBjD9LGDH" +
        "gdzZ7FszBpFwWEEhsGZx5ZQgFexauozom2lfxSLyZRprWySpMCRlqhU/Vgmx4DwXwWimqH/gtD6cK9+88lcMqhC2d+Jy6D2OrhSb" +
        "MMW5chfDW6BETxUBXQRBQ6pG8FfWH+f1WN2jytWvymqmvR31e8XsxUa3oOQUTO+NcKBkI3iH7DMR9N5PWwA5OVTrunAl8eC3cb9Z" +
        "dIG6j27xMjNck46fYAIIp3uqyK1MTC6Z6e8yygL1pSW7/whNWL/4gp0EFyMkx7M1V8QmqYNaeVbRVFjDGZ30qh2Osr4mtEPImvHZ" +
        "FX8Sv0keMYemH9oLqyxYzhsb40XCWNzYC0RS73kTcXATtetNSsXzrxLfbno09jQHsg=="
}

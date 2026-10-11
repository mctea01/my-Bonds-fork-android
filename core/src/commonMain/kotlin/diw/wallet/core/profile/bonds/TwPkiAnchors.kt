package diw.wallet.core.profile.bonds

import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64

/**
 * Taiwan government PKI anchors used by MOICA (citizen digital certificate) checks: the Government Root
 * Certification Authority G3 and the MOICA G3 intermediate it issued (published at moica.nat.gov.tw and grca.nat.gov.tw).
 */
object TwPkiAnchors {
    /** GRCA_G3, SHA-256 57df6f20e04c588e85f35be8832f5d4e78958336ae3b18fb7c9bae0dfead4044. */
    const val GRCA_G3_B64 =
        "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"

    /** MOICA_G3, SHA-256 ed793fd0d50a2a398049d598982cf01e75f873b532066caec238f800a06ca9da. */
    const val MOICA_G3_B64 =
        "MIIGZzCCBE+gAwIBAgIQWiAtFLOXh9CIbDcYSsm3ajANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJUVzESMBAGA1UECgwJ6KGM" +
        "5pS/6ZmiMTUwMwYDVQQDDCxHb3Zlcm5tZW50IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMzAeFw0yNDAxMjMwNjMw" +
        "NDVaFw00NDAxMjMxNTU5NTlaMEcxCzAJBgNVBAYTAlRXMRIwEAYDVQQKDAnooYzmlL/pmaIxJDAiBgNVBAsMG+WFp+aUv+mDqOaG" +
        "keitieeuoeeQhuS4reW/gzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK5a6WTikwWn3sCGPX9XqmZAhgRaf74N7M9C" +
        "Csri5feOnAY0iTx++tzQKbceRCcs0riTxDJN+1JxOOo2/EWxlzcqYLradDC7t5iyUyJ4TzIHUlTOB3pi/B2ft7FkKYdMOoMi9LA+" +
        "q62xbvr8Nn0eE/3mLJkDnC7E6uajhzvZDJmK5KbjLM+blIE/8b8q9qX+x5BtYn4vG4dFKBMn9CTWm4FGSrCQk6FQMINKeYREhmvY" +
        "tFl4nNcx5eSxApaLeRlSg50jquAAJPYEkGnlfrkSYOEkHfK3WslDYT6N2+eOjUaK+mVlz0WHYg7TSnUhc6UmT6I9WfV5P1/WWsBt" +
        "/6U8oARanx6+RmdgsHN/S9XjAq1zMrL/NS6CXVDUZJ+YJWQjaCZ+jFITX+PPBIwuxUg9jIl/sGAOOE6qr2EJPQy2jKHSu1+Ai5vv" +
        "9DkB4as46NkYPGJKlvhGZEHQ+dHS9ZTzNrlAKi+VKrXbNK374gfp2/krz7rCbmOIML/Fq4PRrUPBSu9S49i90ay4VmsT2mMr7NC3" +
        "UvK4L8QtjvRt2R2ilU4WrF3Lv35qYPG9oPFGh1ZoBRN1rjE3AWK1LUtugTxoipyOotqjgZ3Vj4yvb478QA9wVkPbwQlWZTpzQdNb" +
        "//A6P/CveDiVcQICYB0YENlnIS1nXDJvjjkVf14cZzHFJdjvAgMBAAGjggE8MIIBODAfBgNVHSMEGDAWgBQ6kI7nQUcZc9ycvaN+" +
        "2D0+gwkfAzAdBgNVHQ4EFgQURyCjsSZLzW1IrPJkCIaXLHRUEV8wDgYDVR0PAQH/BAQDAgGGMD4GA1UdHwQ3MDUwM6AxoC+GLWh0" +
        "dHA6Ly9ncmNhLm5hdC5nb3YudHcvcmVwb3NpdG9yeS9DUkwzL0NBLmNybDB8BggrBgEFBQcBAQRwMG4wPgYIKwYBBQUHMAKGMmh0" +
        "dHA6Ly9ncmNhLm5hdC5nb3YudHcvcmVwb3NpdG9yeS9DZXJ0cy9HUkNBRzMuY3J0MCwGCCsGAQUFBzABhiBodHRwOi8vb2NzcC5n" +
        "cmNhLm5hdC5nb3YudHcvT0NTUDASBgNVHRMBAf8ECDAGAQH/AgEAMBQGA1UdIAQNMAswCQYHYIZ2ZQADAzANBgkqhkiG9w0BAQsF" +
        "AAOCAgEAj9OlgR+ufc5tXntiTyqu9Bp+T4pea2F7Zs76n3Y7jzqmd6+u6eNSl4ds0KysD8mZIE2v2X+bC2siN2+NUrRwZp2kLPqr" +
        "zzlHJzyHiPS3uvnhsSHC7pOGRifwLmxKm584Fyz5IA15IcCFcglJ2TK/GB2lDSHbUcOt1AZ20EaUcXj4Fb8AwNOZ8VAxt5C+fbaF" +
        "5bczr2FxhxxqaS9Y966EkNkXg7IO6CwOC0TOzKD04T48kvMJisYr+EPF1VNuADOAbrZiCNnVwEufGOhyLIeG2HK163V355H9cvvt" +
        "0kfQoBxIoLTGeoqaF3l0vCHgx8twWV1cSzbuGFBZJ0jEqcY7kWGGU8+E+qrts7po2MzoSdTdEgvivKkIHjFVaq0trDtUklXn6iNa" +
        "eUQWXqZdHutWpk0bhN1596cYOw9ZKPHBYu+Pc5MJazf01xJKkgtri5s0eJu9X5VZAP05Wka2HFMfUyJx8rFHAOhs6Bf6GC6VQS6Y" +
        "5w8etVIGI5Y/6vjmOThBfxTo6StJeAjWpcPHBTGQHep4bQJmgRo7BLa27dsxipIPw2gdO1dqvUNE7wBWyxdrpBuAAoOEHCb/LSw6" +
        "tRv5XiKs7QADYCszOBb3hHzoFql3t6zbxHLVD0Dl69cz3D5U8/PNxMHetFn/lB97ICrzGNryp3RsDKDpfaP0GUF4LKg="

    val grcaG3: X509Cert by lazy { X509Cert(ByteString(GRCA_G3_B64.fromBase64())) }
    val moicaG3: X509Cert by lazy { X509Cert(ByteString(MOICA_G3_B64.fromBase64())) }
}

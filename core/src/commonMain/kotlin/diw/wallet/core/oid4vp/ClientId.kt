package diw.wallet.core.oid4vp

/** OpenID4VP 1.0 Client Identifier Prefixes (section 5.9). */
enum class ClientIdPrefix(val wire: String?) {
    PRE_REGISTERED(null),
    REDIRECT_URI("redirect_uri"),
    X509_SAN_DNS("x509_san_dns"),
    X509_HASH("x509_hash"),
    DECENTRALIZED_IDENTIFIER("decentralized_identifier"),
    VERIFIER_ATTESTATION("verifier_attestation"),
    OPENID_FEDERATION("openid_federation"),
    /** Reserved for the DC API; never accepted from the Verifier. */
    ORIGIN("origin"),
    /** Synthetic identifier the wallet derives for unsigned DC API requests. */
    WEB_ORIGIN("web-origin");

    companion object {
        fun fromWire(w: String): ClientIdPrefix? = entries.firstOrNull { it.wire == w }
    }
}

/** A parsed client_id: prefix plus the part after the prefix. */
data class ClientId(val raw: String, val prefix: ClientIdPrefix, val value: String) {
    companion object {
        /**
         * Parses [raw] per OpenID4VP 1.0: the prefix is the part before the first ':' when it is a known prefix;
         * otherwise the whole value is a pre-registered client identifier.
         */
        fun parse(raw: String): ClientId {
            val idx = raw.indexOf(':')
            if (idx > 0) {
                val p = ClientIdPrefix.fromWire(raw.substring(0, idx))
                if (p != null && p != ClientIdPrefix.PRE_REGISTERED) {
                    return ClientId(raw, p, raw.substring(idx + 1))
                }
            }
            return ClientId(raw, ClientIdPrefix.PRE_REGISTERED, raw)
        }
    }
}

package diw.wallet.core.zktls

import diw.wallet.core.util.ProtocolException

/**
 * The verification pages the wallet knows. A built-in profile is added only after its rules were checked against a
 * real response on a developer's machine (the response itself is never committed). Other pages reach the wallet as
 * a definition inside a request, which is accepted only in the test environment.
 */
object ZkTlsProfiles {
    val builtIn: List<ZkTlsProfile> = emptyList()

    fun find(id: String): ZkTlsProfile? = builtIn.firstOrNull { it.id == id }

    /**
     * The profile [request] names: the built-in one, else its inline definition when [allowInline]. An inline
     * definition may not reuse a built-in id, so a request cannot change what a known page reveals.
     */
    fun resolve(request: ZkTlsSessionRequest, allowInline: Boolean): ZkTlsProfile {
        find(request.profileId)?.let { builtIn ->
            if (request.profileDefinition != null && ZkTlsProfile.parse(request.profileDefinition) != builtIn) {
                throw ProtocolException("invalid_profile", "The request redefines the built-in verification page ${request.profileId}")
            }
            return builtIn
        }
        val definition = request.profileDefinition ?: throw ProtocolException("invalid_profile", "Unknown verification page ${request.profileId}")
        if (!allowInline) throw ProtocolException("invalid_profile", "查驗頁 ${request.profileId} 不是內建的查驗頁，只能在測試環境使用")
        val profile = ZkTlsProfile.parse(definition)
        if (profile.id != request.profileId) throw ProtocolException("invalid_profile", "The verification page does not match the request")
        return profile
    }
}

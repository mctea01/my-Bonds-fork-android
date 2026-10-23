package diw.wallet.core.zktls

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.zk.ZkTemplatePack

/**
 * The verification pages the wallet knows: those of the installed template pack (signed, from a GitHub Release, see
 * [ZkTemplatePack]). A page is added to a pack only after its rules were checked against a real response on a
 * developer's machine (the response itself is never committed). Other pages reach the wallet as a definition inside
 * a request, which is accepted only in the test environment.
 */
object ZkTlsProfiles {
    @Volatile
    private var pack: ZkTemplatePack? = null

    /** Pages of the installed pack. */
    val installed: List<ZkTlsProfile> get() = pack?.zktls.orEmpty()

    /** Version of the installed pack, null when none is installed. */
    val packVersion: Long? get() = pack?.version

    fun install(pack: ZkTemplatePack) {
        val current = this.pack
        if (current == null || pack.version >= current.version) this.pack = pack
    }

    fun find(id: String): ZkTlsProfile? = installed.firstOrNull { it.id == id }

    /**
     * The profile [request] names: the installed one, else its inline definition when [allowInline]. An inline
     * definition may not reuse an installed id, so a request cannot change what a known page reveals.
     */
    fun resolve(request: ZkTlsSessionRequest, allowInline: Boolean): ZkTlsProfile {
        find(request.profileId)?.let { known ->
            if (request.profileDefinition != null && ZkTlsProfile.parse(request.profileDefinition) != known) {
                throw ProtocolException("invalid_profile", "The request redefines the verification page ${request.profileId}")
            }
            return known
        }
        val definition = request.profileDefinition ?: throw ProtocolException("invalid_profile", "查驗頁 ${request.profileId} 不在已安裝的版型包中，請更新版型")
        if (!allowInline) throw ProtocolException("invalid_profile", "查驗頁 ${request.profileId} 不在已安裝的版型包中，只能在測試環境使用")
        val profile = ZkTlsProfile.parse(definition)
        if (profile.id != request.profileId) throw ProtocolException("invalid_profile", "The verification page does not match the request")
        return profile
    }
}

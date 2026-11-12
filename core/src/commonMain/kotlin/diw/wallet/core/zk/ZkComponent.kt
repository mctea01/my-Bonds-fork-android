package diw.wallet.core.zk

/**
 * A native component kept out of the base app because few people need it; the first is Barretenberg 5 for zkPassport
 * proofs of circuits before 0.22.0. On a Google Play install it is an on-demand module; every other package of the
 * app (the APKs on GitHub, the desktop app) carries it already, so all builds offer the same functions.
 */
interface ZkComponent {
    /** Whether it is on this device now. */
    fun present(): Boolean

    /** Whether the app can fetch it itself (Google Play); false when it comes only with a full package of the app. */
    val installable: Boolean

    /** Fetches and installs it, reporting progress from 0 to 1; null on success, else an error code. */
    suspend fun install(progress: (Float) -> Unit): String?

    /** Loads it into the process: the path or name the native loader then opens, or null when it is not here. */
    fun load(): String?
}

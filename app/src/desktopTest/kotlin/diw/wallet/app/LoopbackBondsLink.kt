package diw.wallet.app

import diw.wallet.core.profile.bonds.BondsLinkCollector
import diw.wallet.core.profile.bonds.BondsLinkTransport
import diw.wallet.core.profile.bonds.BondsReception
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update

/**
 * The Bonds BLE link in memory, with the real framing at a small MTU: a holder's peripheral "advertises" a service
 * UUID and a verifier's central on the same loopback finds it, receives the frames and writes framed replies back.
 * [bondsHolder] and [bondsVerifier] make either side behave as the Bonds App does: no reply characteristic on the
 * holder, no verdict from the verifier.
 */
class LoopbackBondsLink(private val mtu: Int = 185) {
    private class Advert(val frames: List<ByteArray>, val takesReplies: Boolean) {
        @Volatile var hello = false
        val received = Channel<Unit>(Channel.CONFLATED)
        val replies = Channel<ByteArray>(Channel.UNLIMITED)
    }

    private val adverts = MutableStateFlow<Map<String, Advert>>(emptyMap())

    @Volatile var bondsHolder = false
    @Volatile var bondsVerifier = false

    /** Frames the last holder sent, to check the framing. */
    @Volatile var lastFrames = 0

    val peripheral = object : BondsLinkPeripheral {
        override suspend fun unavailableReason(): String? = null

        override suspend fun send(serviceUuid: String, presentationJws: String, onProgress: (String) -> Unit): Boolean =
            exchange(serviceUuid, presentationJws.encodeToByteArray(), onProgress) != null

        override suspend fun exchange(serviceUuid: String, payload: ByteArray, onProgress: (String) -> Unit): ByteArray? {
            val advert = Advert(BondsLinkTransport.frames(payload, mtu - 3), !bondsHolder)
            lastFrames = advert.frames.size
            adverts.update { it + (serviceUuid to advert) }
            try {
                onProgress("等待查驗方以藍牙連線")
                advert.received.receive()
                if (!advert.hello) return ByteArray(0)
                onProgress("查驗方已收到，正在驗證")
                val collector = BondsLinkCollector(BondsLinkTransport.REPLY_MAX_PAYLOAD)
                while (true) {
                    val r = collector.accept(advert.replies.receive())
                    if (r is BondsReception.Completed) return r.payload
                }
            } finally {
                adverts.update { it - serviceUuid }
            }
        }
    }

    val central = object : BondsLinkCentral {
        override suspend fun unavailableReason(): String? = null

        override suspend fun receive(
            serviceUuid: String,
            maxPayload: Int,
            onProgress: (String) -> Unit,
            answer: (suspend (ByteArray) -> ByteArray)?,
        ): ByteArray {
            onProgress("等待出示者的手機出現")
            val advert = adverts.first { serviceUuid in it }.getValue(serviceUuid)
            val replies = answer != null && advert.takesReplies && !bondsVerifier
            if (replies) advert.hello = true
            val collector = BondsLinkCollector(maxPayload, BondsLinkTransport.AGE_MAX_CHUNKS)
            // Out of order, as notifications are not, to exercise the collector.
            val payload = advert.frames.indices.reversed().firstNotNullOf { i ->
                (collector.accept(advert.frames[i]) as? BondsReception.Completed)?.payload
            }
            advert.received.send(Unit)
            val verdict = answer?.invoke(payload) ?: return payload
            if (replies) for (frame in BondsLinkTransport.frames(verdict, mtu - 3, BondsLinkTransport.REPLY_MAX_PAYLOAD)) advert.replies.send(frame)
            return payload
        }
    }
}

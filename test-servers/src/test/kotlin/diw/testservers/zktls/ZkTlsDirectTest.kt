package diw.testservers.zktls

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.zktls.ZkTlsDirect
import diw.wallet.core.zktls.ZkTlsDirectRead
import diw.wallet.core.zktls.ZkTlsPlanner
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The holder's own query over this device's TLS: read with the page's rules, inputs and the rest of the page left out. */
class ZkTlsDirectTest {
    private val record = ZkTlsRecordPage

    @Test
    fun foundRecordIsRead() = runBlocking<Unit> {
        for (chunked in listOf(false, true)) {
            ZkTlsTarget(chunked = chunked, responder = record::respond).use { target ->
                val profile = record.profile(target.port)
                val request = ZkTlsPlanner.request(profile, mapOf("serial" to record.SERIAL, "code" to record.CODE))
                val fetched = ZkTlsDirect.fetch(profile, request, listOf(target.caDer))
                assertEquals(2, fetched.certChainDer.size)
                assertTrue(fetched.time > 0)
                val outcome = ZkTlsDirectRead.outcome(profile, request, fetched, "test")
                assertTrue(outcome.passed, outcome.toString())
                assertEquals(mapOf("name" to record.NAME, "date" to record.DATE), outcome.fields)
                assertEquals("localhost", outcome.serverName)
                assertFalse(record.SERIAL in outcome.toString() || record.HIDDEN in outcome.toString() || record.CODE in outcome.toString())
            }
        }
    }

    @Test
    fun missingRecordIsNotFound() = runBlocking<Unit> {
        ZkTlsTarget(responder = record::respond).use { target ->
            val profile = record.profile(target.port)
            val request = ZkTlsPlanner.request(profile, mapOf("serial" to "A123456789", "code" to record.CODE))
            val outcome = ZkTlsDirectRead.outcome(profile, request, ZkTlsDirect.fetch(profile, request, listOf(target.caDer)), "test")
            assertFalse(outcome.found)
            assertFalse(outcome.passed)
        }
    }

    /** Without the test CA the site's certificate is not trusted and nothing is sent. */
    @Test
    fun untrustedSiteIsRefused() = runBlocking<Unit> {
        ZkTlsTarget(responder = record::respond).use { target ->
            val profile = record.profile(target.port)
            val request = ZkTlsPlanner.request(profile, mapOf("serial" to record.SERIAL, "code" to record.CODE))
            assertFailsWith<Exception> { ZkTlsDirect.fetch(profile, request, emptyList()) }
            assertTrue(target.requests.isEmpty())
        }
    }

    /** A certificate that chains to a trusted root but names another host is refused, with the extra roots too. */
    @Test
    fun certificateForAnotherHostIsRefused() = runBlocking<Unit> {
        ZkTlsTarget(responder = record::respond).use { target ->
            val profile = record.profile(target.port, host = "127.0.0.1")
            val request = ZkTlsPlanner.request(profile, mapOf("serial" to record.SERIAL, "code" to record.CODE))
            val e = assertFailsWith<ProtocolException> { ZkTlsDirect.fetch(profile, request, listOf(target.caDer)) }
            assertEquals("untrusted_server", e.code)
            assertTrue(target.requests.isEmpty())
        }
    }

    /** A response larger than the page allows is refused rather than read. */
    @Test
    fun oversizedResponseIsRefused() = runBlocking<Unit> {
        ZkTlsTarget(bodySize = 8192).use { target ->
            val profile = record.profile(target.port)
            val request = ZkTlsPlanner.request(profile, mapOf("serial" to record.SERIAL, "code" to record.CODE))
            val e = runCatching { ZkTlsDirectRead.outcome(profile, request, ZkTlsDirect.fetch(profile, request, listOf(target.caDer)), "test") }.exceptionOrNull()
            assertTrue(e is ProtocolException, e.toString())
        }
    }
}

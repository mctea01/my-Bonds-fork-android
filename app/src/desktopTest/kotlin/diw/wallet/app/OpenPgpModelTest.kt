package diw.wallet.app

import diw.wallet.core.document.DocCrypto
import kotlin.test.Test
import kotlin.test.assertEquals

class OpenPgpModelTest {
    /** The Web Key Directory example (draft-koch-openpgp-webkey-service): joe.doe hashes to this file name. */
    @Test
    fun wkdNameMatchesTheSpecification() {
        val hash = OpenPgpModel.zBase32(DocCrypto.digest("SHA-1", "Joe.Doe".lowercase().encodeToByteArray()))
        assertEquals("iy9q119eutrkn8s1mk4r39qejnbu3n5q", hash)
    }
}

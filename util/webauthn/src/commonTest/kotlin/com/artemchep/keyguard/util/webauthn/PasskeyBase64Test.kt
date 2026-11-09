package com.artemchep.keyguard.util.webauthn

import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PasskeyBase64Test {
    @Test
    fun `stored keys accept both alphabets and optional padding`() {
        val expected = byteArrayOf(0xfb.toByte(), 0xff.toByte())
        for (encoded in listOf("+/8=", "+/8", "-_8=", "-_8")) {
            assertContentEquals(expected, PasskeyBase64.decodeStoredKeyOrNull(encoded))
        }
        assertNull(PasskeyBase64.decodeStoredKeyOrNull("%%%"))
    }

    @Test
    fun `a PRF secret written as standard base64 keeps its bytes`() {
        // Builds before the transport field encoded the secret with the app-wide
        // Base64 encoder, whose alphabet uses '+' and '/' and padding.
        val secret = ByteArray(32) { 0xfb.toByte() }
        val standard = Base64.Default.encode(secret)
        assertTrue('+' in standard, standard)
        assertContentEquals(secret, PasskeyBase64.decodePrfSecretOrNull(standard))
        assertContentEquals(secret, PasskeyBase64.decodePrfSecretOrNull(PasskeyBase64.encodeToString(secret)))
    }

    @Test
    fun `storage decoding does not relax WebAuthn wire decoding`() {
        assertFailsWith<IllegalArgumentException> { PasskeyBase64.decode("+/8=") }
    }
}

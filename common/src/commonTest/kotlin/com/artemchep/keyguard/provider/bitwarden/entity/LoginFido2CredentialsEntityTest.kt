package com.artemchep.keyguard.provider.bitwarden.entity

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Pins the reading of [LoginFido2CredentialsEntity.legacyPrfSecret]. The fork's
 * own builds wrote the PRF secret into the passkey, so documents in vaults that
 * they touched still carry it and must not lose it.
 */
class LoginFido2CredentialsEntityTest {
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    @Test
    fun `the secret of the fork's builds is read from either key`() {
        for (key in listOf("prfSecret", "PrfSecret")) {
            val entity = json.decodeFromString<LoginFido2CredentialsEntity>(passkey(key, "c2VjcmV0"))
            assertEquals("c2VjcmV0", entity.legacyPrfSecret, key)
        }
    }

    @Test
    fun `a passkey without the secret reads none`() {
        val entity = json.decodeFromString<LoginFido2CredentialsEntity>(passkey(name = null, secret = null))
        assertNull(entity.legacyPrfSecret)
    }


    private fun passkey(name: String?, secret: String?): String = buildString {
        append("{")
        append("\"credentialId\":\"cred-1\",")
        append("\"keyValue\":\"AQID\",")
        append("\"rpId\":\"example.com\",")
        append("\"counter\":\"0\",")
        append("\"discoverable\":\"true\",")
        if (name != null && secret != null) {
            append("\"$name\":\"$secret\",")
        }
        append("\"creationDate\":\"1970-01-01T00:00:00Z\"")
        append("}")
    }
}

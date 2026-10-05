package com.artemchep.keyguard.feature.home.vault.add

import com.artemchep.keyguard.common.model.DSecret
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.time.Instant

class AddStateProducerPasskeyTest {
    private val json = Json

    @Test
    fun `edit state conversions and persisted restore preserve independent PRF secret`() {
        val credential = credential(prfSecret = "cHJmLXNlY3JldA==")
        val data = AddStateItemPasskeyFactory.PasskeyData.fromDomain(credential)

        // An unrelated item edit must not change any of the passkey's data.
        assertEquals(credential, data.toDomain())
        val restored = json.decodeFromString<AddStateItemPasskeyFactory.PasskeyData>(
            json.encodeToString(data),
        )
        assertEquals(credential, restored.toDomain())
    }

    @Test
    fun `legacy persisted edit state without PRF secret restores nullable default`() {
        val credential = credential(prfSecret = null)
        val data = AddStateItemPasskeyFactory.PasskeyData.fromDomain(credential)
        val serialized = json.encodeToString(data)

        assertFalse("prfSecret" in json.parseToJsonElement(serialized).jsonObject)
        val restored = json.decodeFromString<AddStateItemPasskeyFactory.PasskeyData>(serialized)
        assertEquals(credential, restored.toDomain())
    }

    private fun credential(prfSecret: String?) = DSecret.Login.Fido2Credentials(
        credentialId = "credential-id",
        keyType = "public-key",
        keyAlgorithm = "ECDSA",
        keyCurve = "P-256",
        keyValue = "private-key",
        prfSecret = prfSecret,
        rpId = "example.com",
        rpName = "Example",
        counter = 3,
        userHandle = "user-handle",
        userName = "alice",
        userDisplayName = "Alice",
        discoverable = true,
        creationDate = Instant.parse("2024-01-01T00:00:00Z"),
    )
}

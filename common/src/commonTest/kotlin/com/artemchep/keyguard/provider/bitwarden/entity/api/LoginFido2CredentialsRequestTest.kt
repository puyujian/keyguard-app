package com.artemchep.keyguard.provider.bitwarden.entity.api

import com.artemchep.keyguard.core.store.bitwarden.BitwardenCipher
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class LoginFido2CredentialsRequestTest {
    @Test
    fun `NodeWarden upload uses lower camel prfSecret field`() {
        val request = LoginFido2CredentialsRequest.of(
            BitwardenCipher.Login.Fido2Credentials(
                credentialId = "2.encrypted-credential-id",
                keyType = "2.encrypted-key-type",
                keyAlgorithm = "2.encrypted-key-algorithm",
                keyCurve = "2.encrypted-key-curve",
                keyValue = "2.encrypted-key-value",
                prfSecret = "2.encrypted-prf-secret",
                rpId = "2.encrypted-rp-id",
                rpName = null,
                counter = "2.encrypted-counter",
                userHandle = null,
                userName = null,
                userDisplayName = null,
                discoverable = "2.encrypted-discoverable",
                creationDate = Instant.parse("2024-01-01T00:00:00Z"),
            ),
        )

        val body = json.parseToJsonElement(json.encodeToString(request)).jsonObject

        assertEquals("2.encrypted-prf-secret", body.getValue("prfSecret").jsonPrimitive.content)
        assertFalse("PrfSecret" in body)
    }

    private companion object {
        val json = Json {
            encodeDefaults = false
            explicitNulls = false
        }
    }
}

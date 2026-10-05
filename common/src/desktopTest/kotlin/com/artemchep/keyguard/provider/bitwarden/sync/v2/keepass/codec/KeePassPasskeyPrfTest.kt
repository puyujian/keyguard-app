package com.artemchep.keyguard.provider.bitwarden.sync.v2.keepass.codec

import app.keemobile.kotpass.models.Entry
import app.keemobile.kotpass.models.EntryValue
import com.artemchep.keyguard.core.store.bitwarden.BitwardenCipher
import com.artemchep.keyguard.provider.bitwarden.sync.v2.keepass.codec.KeePassCipherCodec.EncodedCipher
import com.artemchep.keyguard.provider.bitwarden.sync.v2.keepass.createTestCipherCodec
import com.artemchep.keyguard.provider.bitwarden.sync.v2.keepass.testBitwardenCipher
import com.artemchep.keyguard.util.webauthn.PasskeyBase64
import kotlinx.coroutines.test.runTest
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Instant

class KeePassPasskeyPrfTest {
    private val codec = createTestCipherCodec()
    private val creationDate = Instant.parse("2024-01-01T00:00:00Z")
    private val credential = BitwardenCipher.Login.Fido2Credentials(
        credentialId = "Y3JlZGVudGlhbA",
        keyType = "public-key",
        keyAlgorithm = "ECDSA",
        keyCurve = "P-256",
        keyValue = PasskeyBase64.encodeToString(
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair().private.encoded,
        ),
        prfSecret = "cHJmLXNlY3JldA==",
        rpId = "example.com",
        rpName = null,
        counter = "0",
        userHandle = "dXNlci1oYW5kbGU",
        userName = "alice",
        userDisplayName = "alice",
        discoverable = "true",
        creationDate = creationDate,
    )

    @Test
    fun `PRF credential round trips via concealed blob and survives unrelated edit`() = runTest {
        val encoded = assertPrfBlobRoundTrip(remote = null)
        assertPrfBlobRoundTrip(remote = encoded.entry)
    }

    @Test
    fun `adding PRF secret to existing KPEX credential switches to lossless concealed blob`() = runTest {
        val legacy = codec.encode(
            local = cipher(credential.copy(prfSecret = null)),
            remote = null,
            existingBinaries = emptyMap(),
        )
        assertNotNull(legacy.entry.fields["KPEX_PASSKEY_PRIVATE_KEY_PEM"])

        assertPrfBlobRoundTrip(remote = legacy.entry)
    }

    @Test
    fun `legacy credential without PRF still uses KPEX projection`() = runTest {
        val legacyCredential = credential.copy(prfSecret = null)
        val local = cipher(legacyCredential)
        val encoded = codec.encode(
            local = local,
            remote = null,
            existingBinaries = emptyMap(),
        )

        assertIs<EntryValue.Encrypted>(encoded.entry.fields["KPEX_PASSKEY_PRIVATE_KEY_PEM"])
        assertNull(encoded.entry.fields["FIDO2 Credentials Blob #0"])
        assertEquals(
            listOf(legacyCredential),
            decode(local, encoded).login?.fido2Credentials,
        )
    }

    private suspend fun assertPrfBlobRoundTrip(remote: Entry?): EncodedCipher {
        val local = cipher(credential).copy(name = "Unrelated title edit")
        val encoded = codec.encode(
            local = local,
            remote = remote,
            existingBinaries = emptyMap(),
        )

        assertIs<EntryValue.Encrypted>(encoded.entry.fields["FIDO2 Credentials Blob #0"])
        assertNull(encoded.entry.fields["KPEX_PASSKEY_PRIVATE_KEY_PEM"])
        val decoded = decode(local, encoded)
        assertEquals(listOf(credential), decoded.login?.fido2Credentials)
        assertEquals(local.name, decoded.name)
        assertEquals(emptyList(), decoded.fields)
        return encoded
    }

    private suspend fun decode(local: BitwardenCipher, encoded: EncodedCipher) = codec.decode(
        accountId = local.accountId,
        folderId = null,
        cipherId = local.cipherId,
        remote = encoded.entry,
        local = null,
        revisionDate = creationDate,
        binaries = encoded.binaryAdditions,
    )

    private fun cipher(credential: BitwardenCipher.Login.Fido2Credentials) = testBitwardenCipher(
        cipherId = "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12",
    ).copy(
        createdDate = creationDate,
        type = BitwardenCipher.Type.Login,
        secureNote = null,
        login = BitwardenCipher.Login(
            fido2Credentials = listOf(credential),
            uris = emptyList(),
        ),
    )
}

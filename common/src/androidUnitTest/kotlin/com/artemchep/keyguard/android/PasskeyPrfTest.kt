package com.artemchep.keyguard.android

import com.artemchep.keyguard.common.model.Argon2Mode
import com.artemchep.keyguard.common.model.CryptoHashAlgorithm
import com.artemchep.keyguard.common.service.crypto.CryptoGenerator
import com.artemchep.keyguard.common.service.passkey.entity.CreatePasskeyPrfEvalInput
import com.artemchep.keyguard.common.service.passkey.entity.CreatePasskeyPrfExtension
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PasskeyPrfTest {
    private val cryptoGenerator = JvmCryptoGenerator()

    @Test
    fun `PRF 单输入符合规范且输出 32 字节`() {
        val secret = "test-prf-secret".encodeToByteArray()
        val input = "test-prf-input".encodeToByteArray()
        val salt = MessageDigest.getInstance("SHA-256")
            .digest(PasskeyUtils.PRF_LABEL + input)
        val expected = hmacSha256(secret, salt)

        val actual = computeWebAuthnPrf(cryptoGenerator, secret, input)

        assertEquals(32, actual.size)
        assertContentEquals(expected, actual)
    }

    @Test
    fun `相同 secret 和输入产生确定输出`() {
        val secret = "credential-secret".encodeToByteArray()
        val input = "input".encodeToByteArray()

        assertContentEquals(
            computeWebAuthnPrf(cryptoGenerator, secret, input),
            computeWebAuthnPrf(cryptoGenerator, secret, input),
        )
    }

    @Test
    fun `不同输入产生不同输出`() {
        val secret = "credential-secret".encodeToByteArray()

        val first = computeWebAuthnPrf(cryptoGenerator, secret, "first".encodeToByteArray())
        val second = computeWebAuthnPrf(cryptoGenerator, secret, "second".encodeToByteArray())

        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `不同 credential secret 产生不同输出`() {
        val input = "same-input".encodeToByteArray()

        val first = computeWebAuthnPrf(cryptoGenerator, "secret-a".encodeToByteArray(), input)
        val second = computeWebAuthnPrf(cryptoGenerator, "secret-b".encodeToByteArray(), input)

        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `PRF 不再使用签名私钥派生方案`() {
        val signingKey = "signing-private-key".encodeToByteArray()
        val secret = "separate-prf-secret".encodeToByteArray()
        val input = "input".encodeToByteArray()
        val salt = MessageDigest.getInstance("SHA-256")
            .digest(PasskeyUtils.PRF_LABEL + input)
        val oldKey = hmacSha256(signingKey, "prf".encodeToByteArray())
        val oldOutput = hmacSha256(oldKey, salt)

        val actual = computeWebAuthnPrf(cryptoGenerator, secret, input)

        assertFalse(oldOutput.contentEquals(actual))
    }

    @Test
    fun `二维码 Hybrid 已哈希输入不会被重复哈希`() {
        val secret = ByteArray(32) { it.toByte() }
        val rawInput = "passwordless-login".encodeToByteArray()
        val hashedInput = MessageDigest.getInstance("SHA-256")
            .digest(PasskeyUtils.PRF_LABEL + rawInput)

        val regularOutput = computeWebAuthnPrf(cryptoGenerator, secret, rawInput)
        val hybridOutput = computeWebAuthnPrfFromHashedInput(
            cryptoService = cryptoGenerator,
            prfSecretBytes = secret,
            hashedPrfInput = hashedInput,
        )

        assertContentEquals(regularOutput, hybridOutput)
        assertFalse(
            hybridOutput.contentEquals(
                computeWebAuthnPrf(cryptoGenerator, secret, hashedInput),
            ),
        )
    }

    @Test
    fun `创建响应声明 PRF 并返回单输入结果`() {
        val secret = ByteArray(32) { it.toByte() }
        val result = createPasskeyPrfExtensionResult(
            extension = CreatePasskeyPrfExtension(
                eval = CreatePasskeyPrfEvalInput(first = "first"),
            ),
            userVerified = true,
            prfSecretBytes = secret,
            computePrf = { key, input -> cryptoGenerator.compute(key, input) },
            decodeInput = String::encodeToByteArray,
            encodeOutput = ByteArray::toHex,
        )

        assertNotNull(result)
        assertTrue(result.getValue("enabled").jsonPrimitive.boolean)
        val results = result.getValue("results").jsonObject
        assertEquals(
            cryptoGenerator.compute(secret, "first".encodeToByteArray()).toHex(),
            results.getValue("first").jsonPrimitive.content,
        )
        assertFalse("second" in results)
    }

    @Test
    fun `创建响应支持 PRF 双输入`() {
        val result = createPasskeyPrfExtensionResult(
            extension = CreatePasskeyPrfExtension(
                eval = CreatePasskeyPrfEvalInput(first = "first", second = "second"),
            ),
            userVerified = true,
            prfSecretBytes = ByteArray(32) { 7 },
            computePrf = { key, input -> cryptoGenerator.compute(key, input) },
            decodeInput = String::encodeToByteArray,
            encodeOutput = ByteArray::toHex,
        )

        val results = assertNotNull(result).getValue("results").jsonObject
        assertTrue("first" in results)
        assertTrue("second" in results)
        assertNotEquals(
            results.getValue("first").jsonPrimitive.content,
            results.getValue("second").jsonPrimitive.content,
        )
    }

    @Test
    fun `创建时未完成用户验证不返回 PRF 输出`() {
        val result = createPasskeyPrfExtensionResult(
            extension = CreatePasskeyPrfExtension(
                eval = CreatePasskeyPrfEvalInput(first = "first"),
            ),
            userVerified = false,
            prfSecretBytes = ByteArray(32),
            computePrf = { key, input -> cryptoGenerator.compute(key, input) },
            decodeInput = String::encodeToByteArray,
            encodeOutput = ByteArray::toHex,
        )

        assertNotNull(result)
        assertTrue(result.getValue("enabled").jsonPrimitive.boolean)
        assertFalse("results" in result)
    }

    @Test
    fun `认证解析通用 eval`() {
        val input = resolvePasskeyPrfEvalInput(
            requestJson = requestJson(
                """"eval":{"first":"global-first","second":"global-second"}""",
            ),
            credentialIdBytes = "credential-a".encodeToByteArray(),
            json = json,
            encodeCredentialId = ByteArray::decodeToString,
        )

        val resolvedInput = assertNotNull(input)
        assertFalse(resolvedInput.alreadyHashed)
        assertEquals("global-first", resolvedInput.evalInput.first)
        assertEquals("global-second", resolvedInput.evalInput.second)
    }

    @Test
    fun `认证按当前 credential 选择 evalByCredential`() {
        val requestJson = requestJson(
            """
            "eval":{"first":"fallback"},
            "evalByCredential":{
              "credential-a":{"first":"input-a"},
              "credential-b":{"first":"input-b","second":"input-b-2"}
            }
            """.trimIndent(),
        )

        val first = resolvePasskeyPrfEvalInput(
            requestJson = requestJson,
            credentialIdBytes = "credential-a".encodeToByteArray(),
            json = json,
            encodeCredentialId = ByteArray::decodeToString,
        )
        val second = resolvePasskeyPrfEvalInput(
            requestJson = requestJson,
            credentialIdBytes = "credential-b".encodeToByteArray(),
            json = json,
            encodeCredentialId = ByteArray::decodeToString,
        )

        assertEquals("input-a", first?.evalInput?.first)
        assertEquals("input-b", second?.evalInput?.first)
        assertEquals("input-b-2", second?.evalInput?.second)
    }

    @Test
    fun `二维码 Hybrid 解析已哈希的 evalByCredential`() {
        val credentialHash = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { it.toByte() })
        val rotationHash = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { (it + 1).toByte() })
        val requestJson =
            """
            {
              "challenge":"YQ",
              "rpId":"example.com",
              "extensions":{
                "prfAlreadyHashed":{
                  "eval":{"first":"fallback-hash"},
                  "evalByCredential":{
                    "credential-a":{"first":"$credentialHash","second":"$rotationHash"}
                  }
                }
              }
            }
            """.trimIndent()

        val input = resolvePasskeyPrfEvalInput(
            requestJson = requestJson,
            credentialIdBytes = "credential-a".encodeToByteArray(),
            json = json,
            encodeCredentialId = ByteArray::decodeToString,
        )

        assertNotNull(input)
        assertTrue(input.alreadyHashed)
        assertEquals(credentialHash, input.evalInput.first)
        assertEquals(rotationHash, input.evalInput.second)
    }

    @Test
    fun `认证拒绝同时出现普通和已哈希 PRF 扩展`() {
        val input = resolvePasskeyPrfEvalInput(
            requestJson =
                """
                {
                  "extensions":{
                    "prf":{"eval":{"first":"raw"}},
                    "prfAlreadyHashed":{"eval":{"first":"hashed"}}
                  }
                }
                """.trimIndent(),
            credentialIdBytes = "credential-a".encodeToByteArray(),
            json = json,
            encodeCredentialId = ByteArray::decodeToString,
        )

        assertNull(input)
    }

    @Test
    fun `旧凭据没有 prfSecret 时认证返回空 PRF 对象`() {
        val result = createGetPasskeyPrfExtensionResult(
            evalInput = GetPasskeyPrfEvalInput(first = "first"),
            userVerified = true,
            prfSecretBytes = null,
            computePrf = { key, input -> cryptoGenerator.compute(key, input) },
            decodeInput = String::encodeToByteArray,
            encodeOutput = ByteArray::toHex,
        )

        assertNotNull(result)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `认证未完成用户验证时返回空 PRF 对象`() {
        val result = createGetPasskeyPrfExtensionResult(
            evalInput = GetPasskeyPrfEvalInput(first = "first"),
            userVerified = false,
            prfSecretBytes = ByteArray(32),
            computePrf = { key, input -> cryptoGenerator.compute(key, input) },
            decodeInput = String::encodeToByteArray,
            encodeOutput = ByteArray::toHex,
        )

        assertNotNull(result)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `认证响应支持双输入结果`() {
        val result = createGetPasskeyPrfExtensionResult(
            evalInput = GetPasskeyPrfEvalInput(first = "first", second = "second"),
            userVerified = true,
            prfSecretBytes = ByteArray(32) { 3 },
            computePrf = { key, input -> cryptoGenerator.compute(key, input) },
            decodeInput = String::encodeToByteArray,
            encodeOutput = ByteArray::toHex,
        )

        val results = assertNotNull(result).getValue("results").jsonObject
        assertTrue("first" in results)
        assertTrue("second" in results)
    }

    @Test
    fun `缺失或长度错误的存储 secret 不会进入计算`() {
        assertNull(decodeStoredPrfSecretOrNull(null) { error("不应解码") })
        assertNull(decodeStoredPrfSecretOrNull("broken") { ByteArray(31) })
        assertEquals(32, decodeStoredPrfSecretOrNull("valid") { ByteArray(32) }?.size)
    }

    private fun requestJson(prfMembers: String): String =
        """{"challenge":"YQ","rpId":"example.com","extensions":{"prf":{$prfMembers}}}"""

    private fun JvmCryptoGenerator.compute(secret: ByteArray, input: ByteArray): ByteArray =
        computeWebAuthnPrf(this, secret, input)

    private companion object {
        val json = Json { ignoreUnknownKeys = true }
    }
}

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
    byte.toUByte().toString(radix = 16).padStart(2, '0')
}

private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(data)
    }

private class JvmCryptoGenerator : CryptoGenerator {
    override fun hmac(
        key: ByteArray,
        data: ByteArray,
        algorithm: CryptoHashAlgorithm,
    ): ByteArray {
        val name = when (algorithm) {
            CryptoHashAlgorithm.SHA_1 -> "HmacSHA1"
            CryptoHashAlgorithm.SHA_256 -> "HmacSHA256"
            CryptoHashAlgorithm.SHA_512 -> "HmacSHA512"
            CryptoHashAlgorithm.MD5 -> "HmacMD5"
        }
        return Mac.getInstance(name).run {
            init(SecretKeySpec(key, name))
            doFinal(data)
        }
    }

    override fun hashSha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    override fun hashSha1(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(data)

    override fun hashMd5(data: ByteArray): ByteArray =
        MessageDigest.getInstance("MD5").digest(data)

    override fun hkdf(seed: ByteArray, salt: ByteArray?, info: ByteArray?, length: Int): ByteArray =
        error("测试未使用")

    override fun pbkdf2(seed: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray =
        error("测试未使用")

    override fun argon2(
        mode: Argon2Mode,
        seed: ByteArray,
        salt: ByteArray,
        iterations: Int,
        memoryKb: Int,
        parallelism: Int,
    ): ByteArray = error("测试未使用")

    override fun seed(length: Int): ByteArray = ByteArray(length)

    override fun uuid(): String = "00000000-0000-0000-0000-000000000000"

    override fun random(): Int = 0

    override fun random(range: IntRange): Int = range.first
}

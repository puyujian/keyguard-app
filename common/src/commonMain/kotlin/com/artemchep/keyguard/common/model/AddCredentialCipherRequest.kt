package com.artemchep.keyguard.common.model

sealed interface AddCredentialCipherRequestData

data class AddCredentialCipherRequestPasskeyData(
    val credentialId: String?,
    val keyType: String, // public-key
    val keyAlgorithm: String, // ECDSA
    val keyCurve: String, // P-256
    val keyValue: String,
    /** Base64 编码的 32 字节随机 PRF 密钥；不支持 PRF 的平台可省略。 */
    val prfSecret: String? = null,
    val rpId: String,
    val rpName: String?,
    val counter: Int?,
    val userHandle: String,
    val userName: String?,
    val userDisplayName: String?,
    val discoverable: Boolean,
) : AddCredentialCipherRequestData

data class AddCredentialCipherRequestPasswordData(
    val id: String,
    val password: String,
    val callingAppInfo: CallingAppInfo,
) : AddCredentialCipherRequestData {
    data class CallingAppInfo(
        val origin: String,
        val packageName: String,
    )
}

data class AddCredentialCipherRequest(
    val cipherId: String,
    val data: AddCredentialCipherRequestData,
)

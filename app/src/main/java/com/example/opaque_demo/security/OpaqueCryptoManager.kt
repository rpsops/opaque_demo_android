package com.example.opaque_demo.security

import android.content.Context
import com.example.opaque_demo.R
import com.example.opaque_demo.model.PayloadWrapper
import com.example.opaque_demo.model.RequestPayload
import com.example.opaque_demo.model.ServerPayloadWrapper
import com.example.opaque_demo.model.ServerResponsePayload
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.InputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.time.Instant

class OpaqueCryptoManager(private val context: Context) {

    private val serverPublicKey: ECPublicKey by lazy { getServerPublicKey(context) }
    private val clientPrivateKey: ECPrivateKey by lazy { getClientPrivateKey(context) }

    fun createSignedJws(
        type: String,
        nonce: String,
        encryptedPayload: ByteArray
    ): JWSObject {
        val payloadWrapper = getPayloadWrapper(type, nonce, encryptedPayload)
        
        // create JWSObject
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JOSE).build()
        val serializedPayload = Payload(Json.encodeToString(payloadWrapper).toByteArray())
        val jwsObject = JWSObject(
            header,
            serializedPayload
        )

        // sign JWS
        val signer = ECDSASigner(clientPrivateKey)
        jwsObject.sign(signer)
        return jwsObject
    }

    fun encryptPayload(payload: RequestPayload): ByteArray {
        val payloadBytes = Json.encodeToString(payload).toByteArray()
        return encryptBytes(payloadBytes)
    }

    fun encryptBytes(payload: ByteArray): ByteArray {
        val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).build()
        val jweObject = JWEObject(header, Payload(payload))
        val encrypter = ECDHEncrypter(serverPublicKey)
        jweObject.encrypt(encrypter)
        return jweObject.serialize().toByteArray()
    }

    fun extractPayloadWrapper(serverResponse: String): ServerPayloadWrapper {
        val serverResponseJws = JWSObject.parse(serverResponse)

        // verify signature
        val jwsVerifier = ECDSAVerifier(serverPublicKey)
        if (!serverResponseJws.verify(jwsVerifier)) {
            throw Exception("Invalid signature")
        }

        // get the PayloadWrapper
        val serverPayloadWrapper =
            Json.decodeFromString<ServerPayloadWrapper>(serverResponseJws.payload.toString())

        return serverPayloadWrapper
    }

    fun decryptServerPayload(serverPayloadWrapper: ServerPayloadWrapper): ServerResponsePayload {
        val payloadJwe = JWEObject.parse(String(serverPayloadWrapper.data))
        val decryptor = ECDHDecrypter(clientPrivateKey)
        payloadJwe.decrypt(decryptor)
        val payload =
            Json.decodeFromString<ServerResponsePayload>(payloadJwe.payload.toString())
        return payload
    }

    fun generateNonce(): String {
        val nonceBytes = ByteArray(32)
        SecureRandom().nextBytes(nonceBytes)
        return nonceBytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun getPayloadWrapper(type: String, nonce: String, encryptedPayload: ByteArray) =
        PayloadWrapper(
            "https://wallets/digg.se/1234567890",
            "wallet-hsm-key-1",
            "hsm",
            type,
            null,
            "1.0",
            nonce,
            Instant.now(),
            "device",
            encryptedPayload
        )

    private fun getServerPublicKey(context: Context): ECPublicKey {
        val inputStream: InputStream = context.resources.openRawResource(R.raw.serverkey)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(inputStream)
        return certificate.publicKey as ECPublicKey
    }

    private fun getClientPrivateKey(context: Context): ECPrivateKey {
        val password = "Test1234".toCharArray()
        val alias = "wallet-hsm"
        val keyStore = KeyStore.getInstance("PKCS12")
        context.resources.openRawResource(R.raw.wallethsm).use { inputStream ->
            keyStore.load(inputStream, password)
        }
        return keyStore.getKey(alias, password) as ECPrivateKey
    }
}

package com.example.opaque_demo

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import se.digg.opaque_ke_uniffi.clientLoginFinish
import se.digg.opaque_ke_uniffi.clientLoginStart
import se.digg.opaque_ke_uniffi.clientRegistrationFinish
import se.digg.opaque_ke_uniffi.clientRegistrationStart
import se.digg.opaque_ke_uniffi.serverLoginFinish
import se.digg.opaque_ke_uniffi.serverLoginStart
import se.digg.opaque_ke_uniffi.serverRegistrationFinish
import se.digg.opaque_ke_uniffi.serverRegistrationStart
import se.digg.opaque_ke_uniffi.serverSetup
import java.io.InputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.time.Instant

class RegisterViewModel : ViewModel() {

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    fun register() {
        val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

        val serverSetup = serverSetup();
        val serverRegStartResult =
            serverRegistrationStart(
                serverSetup,
                clientRegStartResult.registrationRequest,
                byteArrayOf(1, 2)
            )

        val clientRegFinishResult = clientRegistrationFinish(
            byteArrayOf(1, 2, 3),
            clientRegStartResult.clientRegistration,
            serverRegStartResult
        )

        val passwordFile =
            serverRegistrationFinish(clientRegFinishResult.registrationUpload)

        val startTime = System.currentTimeMillis()

        val clientLoginStart = clientLoginStart(byteArrayOf(1, 2, 3))

        val endClient1 = System.currentTimeMillis()
        val serverLoginStart = serverLoginStart(
            serverSetup,
            passwordFile,
            clientLoginStart.credentialRequest,
            byteArrayOf(1, 2)
        )

        val startClient = System.currentTimeMillis()
        val clientLoginFinish = clientLoginFinish(
            serverLoginStart.credentialResponse,
            clientLoginStart.clientRegistration,
            byteArrayOf(1, 2, 3)
        )
        val endClient2 = System.currentTimeMillis()

        val clientSessionKey = clientLoginFinish.sessionKey

        val serverLoginFinish = serverLoginFinish(
            serverLoginStart.serverLogin,
            clientLoginFinish.credentialFinalization
        )

        val serverSessionKey = serverLoginFinish

        val endTime = System.currentTimeMillis()
        Log.d("OpaqueDemo", "Opaque process took ${endTime - startTime} ms")
        Log.d(
            "OpaqueDemo",
            "Client took ${(endClient1 - startTime) + (endClient2 - startClient)} ms"
        )
        _result.value =
            "Opaque process took ${endTime - startTime} ms\n Client took ${(endClient1 - startTime) + (endClient2 - startClient)} ms"
    }

    fun testJWS(context: Context) {
        val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

        // this is the blind that we'll save for later
        val clientRegistration = clientRegStartResult.clientRegistration

        // result to send to server
        val registrationRequest = clientRegStartResult.registrationRequest

        // create the payload
        val payload = Payload("opaque", "evaluate", null, registrationRequest)

        // encrypt the payload
        val encryptedPayload = encryptPayload(payload, context)

        // wrap the payload
        val payloadWrapper = PayloadWrapper(
            "https://wallets/digg.se/1234567890",
            "wallet-hsm-key-1",
            "hsm",
            "pin_registration",
            null,
            "1.0",
            "1234567890",
            Instant.now(),
            "device",
            encryptedPayload
        )

        // create JWSObject
        // todo hard coded
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JOSE).build()
        val serializedPayload = com.nimbusds.jose.Payload(Json.encodeToString(payloadWrapper).toByteArray())
        val jwsObject = JWSObject(
            header,
            serializedPayload
        )

        // sign JWS
        val signer = getSigner(context)
        jwsObject.sign(signer)

        // result to send to server
        var jwsString = jwsObject.serialize()


    }

    private fun encryptPayload(payload: Payload, context: Context): ByteArray {

        val payloadBytes = Json.encodeToString(payload).toByteArray()

        // todo check is contentType is really useful here
        val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .contentType("application/octet-stream").build()


        val jweObject = JWEObject(header, com.nimbusds.jose.Payload(payloadBytes))

        val serverPublicKey = getServerPublicKey(context)

        val encrypter = ECDHEncrypter(serverPublicKey)

        jweObject.encrypt(encrypter)
        return jweObject.serialize().toByteArray()
    }

    private fun getServerPublicKey(context: Context): ECPublicKey {
        val inputStream: InputStream = context.resources.openRawResource(R.raw.serverkey)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(inputStream)
        return certificate.publicKey as ECPublicKey
    }

    private fun getSigner(context: Context): ECDSASigner {
        val password = "Test1234".toCharArray()
        val alias = "wallet-hsm"

        val keyStore = KeyStore.getInstance("PKCS12")

        context.resources.openRawResource(R.raw.wallethsm).use { inputStream ->
            keyStore.load(inputStream, password)
        }

        val privateKey = keyStore.getKey(alias, password) as ECPrivateKey
        return ECDSASigner(privateKey)
    }

    // we're probably not going to use context
    @Serializable
    private data class PayloadWrapper(
        val client_id: String,
        val kid: String,
        val context: String,
        val type: String,
        val pake_session_id: String?,
        val ver: String,
        val nonce: String,
        @Serializable(with = InstantEpochSecondsSerializer::class)
        val iat: Instant,
        val enc: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val data: ByteArray
    )

    private object InstantEpochSecondsSerializer : KSerializer<Instant> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("Instant", PrimitiveKind.LONG)

        override fun serialize(encoder: Encoder, value: Instant) =
            encoder.encodeLong(value.epochSecond)

        override fun deserialize(decoder: Decoder): Instant =
            Instant.ofEpochSecond(decoder.decodeLong())
    }

    private object Base64ByteArraySerializer : KSerializer<ByteArray> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("Base64ByteArray", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: ByteArray) {
            encoder.encodeString(java.util.Base64.getEncoder().encodeToString(value))
        }

        override fun deserialize(decoder: Decoder): ByteArray {
            return java.util.Base64.getDecoder().decode(decoder.decodeString())
        }
    }

    @Serializable
    private data class Payload(
        val protocol: String,
        val state: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val authorization: ByteArray?,
        @Serializable(with = Base64ByteArraySerializer::class)
        val req: ByteArray
    )


}

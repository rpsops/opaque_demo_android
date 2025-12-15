package com.example.opaque_demo.security

import android.content.Context
import com.example.opaque_demo.R
import com.example.opaque_demo.model.PayloadWrapper
import com.example.opaque_demo.model.RequestPayload
import com.example.opaque_demo.model.ServerPayloadWrapper
import com.example.opaque_demo.model.ServerResponsePayload
import com.example.opaque_demo.utils.toHexString
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
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import se.digg.opaque_ke_uniffi.hashToCurveP256Sha256
import java.io.InputStream
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECPoint as JavaECPoint
import java.time.Instant
import javax.crypto.KeyAgreement

class OpaqueCryptoManager(private val context: Context, private val clientIdentifier: String) {

    private val serverPublicKey: ECPublicKey by lazy { getServerPublicKey(context) }
    private val clientPrivateKey: ECPrivateKey by lazy { getClientPrivateKey(context) }

    fun createSignedJws(
        type: String,
        nonce: String,
        encryptedPayload: ByteArray,
        pakeSessionId: String?
    ): JWSObject {
        val payloadWrapper = getPayloadWrapper(type, nonce, encryptedPayload, pakeSessionId)

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
        return Json.decodeFromString<ServerPayloadWrapper>(serverResponseJws.payload.toString())
    }

    fun decryptServerPayload(serverPayloadWrapper: ServerPayloadWrapper): ServerResponsePayload {
        val payloadJwe = JWEObject.parse(String(serverPayloadWrapper.data))
        val decryptor = ECDHDecrypter(clientPrivateKey)
        payloadJwe.decrypt(decryptor)
        return Json.decodeFromString<ServerResponsePayload>(payloadJwe.payload.toString())
    }

    fun generateNonce(): String {
        val nonceBytes = ByteArray(32)
        SecureRandom().nextBytes(nonceBytes)
        return nonceBytes.toHexString()
    }


    fun stretchPin(pin: ByteArray): ByteArray {
        val curveName = "secp256r1"

        // 1. Hash to Curve (Get compressed bytes)
        val compressedPoint = hashToCurveP256Sha256(
            pin,
            "SE_EIDAS_WALLET_PIN_HARDENING".toByteArray()
        )

        // 2. Decode Point (Using BC because Java can't handle compressed bytes easily)
        val bcCurve = ECNamedCurveTable.getParameterSpec(curveName)
        val bouncyCastlePoint: ECPoint = bcCurve.curve.decodePoint(compressedPoint)

        // 3. Reconstruct Java Public Key
        val parameterSpec = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec(curveName))
        }.getParameterSpec(ECParameterSpec::class.java)

        val javaPoint = JavaECPoint(
            bouncyCastlePoint.affineXCoord.toBigInteger(),
            bouncyCastlePoint.affineYCoord.toBigInteger()
        )

        val pinPublicKey = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(javaPoint, parameterSpec))

        // 4. ECDH
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(clientPrivateKey)
        keyAgreement.doPhase(pinPublicKey, true)
        val ikm = keyAgreement.generateSecret()

        // 5. HKDF
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, null, byteArrayOf()))
        val seededPin = ByteArray(32)
        hkdf.generateBytes(seededPin, 0, 32)

        return seededPin
    }


    private fun getPayloadWrapper(
        type: String,
        nonce: String,
        encryptedPayload: ByteArray,
        pakeSessionId: String?
    ) =
        PayloadWrapper(
            clientIdentifier,
            "wallet-hsm-key-1",
            "hsm",
            type,
            pakeSessionId,
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

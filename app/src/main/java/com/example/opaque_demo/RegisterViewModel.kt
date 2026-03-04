package com.example.opaque_demo

import android.app.Application
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.opaque_demo.network.OpaqueService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import se.digg.wallet.access_mechanism.api.OpaqueClient
import se.digg.wallet.access_mechanism.exception.OpaqueException
import se.digg.wallet.access_mechanism.model.KeyInfo
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import java.io.InputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class RegisterViewModel(application: Application) : AndroidViewModel(application) {

    private val service = OpaqueService()

    val clientIdentifier = "a25d8884-c77b-43ab-bf9d-1279c08d860d"
    val serverIdentifier = "dev.cloud-wallet.digg.se"

    private val _keys = MutableStateFlow<List<KeyInfo>>(emptyList())
    val keys = _keys.asStateFlow()

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    var sessionKey: ByteArray? = null
    var pakeSessionId: String? = null

    private val _authorizationCode = MutableStateFlow<String?>(null)
    val authorizationCode = _authorizationCode.asStateFlow()

    private val opaqueApi: OpaqueClient by lazy {
        OpaqueClient(
            getServerPublicKey(),
            getClientKeyPair(),
            getPinStretchPrivateKey(),
            serverIdentifier,
            "RPS-Ops"
        )
    }

    fun registerNewState() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val publicKey = getClientKeyPair().public as ECPublicKey
                val tempJwk = ECKey.Builder(Curve.P_256, publicKey).build()
                val kid = tempJwk.computeThumbprint().toString()
                val jwk = ECKey.Builder(Curve.P_256, publicKey).keyID(kid).build()

                val stateRequest = StateRequest(
                    publicKey = jwk,
                    overwrite = true,
                    clientId = clientIdentifier,
                    ttl = "PT10M"
                )

                val registerState = service.registerState(stateRequest)
                Log.d("OpaqueDemo", "Register state response: $registerState")
                _authorizationCode.value = registerState.devAuthorizationCode
                _result.value = "State registered. Code: ${registerState.devAuthorizationCode}"
            } catch (e: Exception) {
                Log.e("OpaqueDemo", "Error registering state", e)
                _result.value = "Error registering state: ${e.message}"
            }
        }
    }

    /**
     * Register a pin (123) for the device
     */
    fun registerPin() {
        _keys.value = emptyList()
        val code = _authorizationCode.value
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pin = "123"
                val registrationStart = opaqueApi.registrationStart(pin, code!!)

                val registrationResponse = service.sendRequest(
                    createBffRequest(registrationStart.registrationRequest)
                )

                val registerFinish = opaqueApi.registrationFinish(
                    pin,
                    code,
                    registrationResponse,
                    registrationStart.clientRegistration
                )

                val serverFinish = service.sendRequest(
                    createBffRequest(registerFinish.registrationUpload)
                )

                val status = opaqueApi.decryptStatus(serverFinish)
                _result.value = status
            } catch (e: OpaqueException) {
                when (e) {
                    is OpaqueException.InvalidInputException -> _result.value =
                        "Invalid input: ${e.message}"

                    is OpaqueException.CryptoException -> _result.value =
                        "Crypto error: ${e.message}"

                    is OpaqueException.ProtocolException -> _result.value =
                        "Protocol error: ${e.message}"
                }
            }
        }
    }

    fun changePin() {
        _keys.value = emptyList()
    viewModelScope.launch(Dispatchers.IO) {
            try {
                val pin = "456"
                val registrationStart = opaqueApi.changePinStart( pin, sessionKey!!, pakeSessionId!!)

                val registrationResponse = service.sendRequest(
                    createBffRequest(registrationStart.registrationRequest)
                )

                Log.d("OpaqueDemo", "Change PIN response: $registrationResponse")

                val registerFinish = opaqueApi.changePinFinish(
                    pin,
                    registrationResponse,
                    registrationStart.clientRegistration,
                    sessionKey!!,
                    pakeSessionId!!
                )

                val serverFinish = service.sendRequest(
                    createBffRequest(registerFinish.registrationUpload)
                )

                val status = opaqueApi.decryptPayload(serverFinish, sessionKey!!)
                _result.value = status
            } catch (e: OpaqueException) {
                when (e) {
                    is OpaqueException.InvalidInputException -> _result.value =
                        "Invalid input: ${e.message}"

                    is OpaqueException.CryptoException -> _result.value =
                        "Crypto error: ${e.message}"

                    is OpaqueException.ProtocolException -> _result.value =
                        "Protocol error: ${e.message}"
                }
            }
        }
    }


    fun createSession() {
        _keys.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pin = "123"
                val loginStart = opaqueApi.loginStart(pin)

                val serverStart = service.sendRequest(createBffRequest(loginStart.loginRequest))

                val loginFinish = opaqueApi.loginFinish(
                    pin, serverStart, loginStart.clientRegistration
                )

                service.sendRequest(createBffRequest(loginFinish.loginFinishRequest))

                // saves the session key and pake session id for later use
                sessionKey = loginFinish.sessionKey
                pakeSessionId = loginFinish.pakeSessionId

                _result.value = loginFinish.sessionKey.joinToString("") { "%02x".format(it) }
            } catch (e: Exception) {
                _result.value = "Login failed: ${e.message}"
            }
        }
    }

    fun createHsmKey() {
        _keys.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            val createHsmKey = opaqueApi.createHsmKey(sessionKey!!, pakeSessionId!!)

            val serverResponse = service.sendRequest(createBffRequest(createHsmKey))
            val payload = opaqueApi.decryptPayload(serverResponse, sessionKey!!)
            _result.value = payload
        }
    }

    suspend fun listHsmKey(): List<KeyInfo> = withContext(Dispatchers.IO) {
        val createHsmKey =
            // todo better naming. It's not listing, it's creating a request to send
            opaqueApi.listHsmKeys(sessionKey!!, pakeSessionId!!)

        val serverResponse = service.sendRequest(createBffRequest(createHsmKey))
        val keys = opaqueApi.decryptKeys(serverResponse, sessionKey!!)
        _keys.value = keys
        _result.value = keys.joinToString("\n\n---\n\n") { key ->
            "Key ID: ${key.publicKey.keyID}\nCreated: ${key.createdAt}"
        }
        keys
    }

    fun sign(key: KeyInfo) {
        _keys.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            val payloadToSign = "{\"payload\":\"test\"}"
            val signRequest =
                opaqueApi.signWithHsm(sessionKey!!, pakeSessionId!!, key.publicKey.keyID, payloadToSign)

            val serverResponse = service.sendRequest(createBffRequest(signRequest.request))
            val signedString =
                opaqueApi.decryptSign(sessionKey!!, signRequest, serverResponse, key.publicKey)

            _result.value = signedString + "\n\n" + key.publicKey.toString()
        }
    }

    fun deleteKey(key: KeyInfo) {
        _keys.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            val createHsmKey =
                opaqueApi.deleteHsmKey(sessionKey!!, pakeSessionId!!, key.publicKey.keyID)

            val serverResponse = service.sendRequest(createBffRequest(createHsmKey))
            val payload = opaqueApi.decryptPayload(serverResponse, sessionKey!!)
            _result.value = payload
        }
    }

    private fun getServerPublicKey(): ECPublicKey {
        val inputStream: InputStream =
            getApplication<Application>().resources.openRawResource(R.raw.serverkey)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(inputStream)
        return certificate.publicKey as ECPublicKey
    }

    private fun getClientKeyPair(): KeyPair {
        val password = "Test1234".toCharArray()
        val alias = "wallet-hsm"
        val keyStore = KeyStore.getInstance("PKCS12")
        getApplication<Application>().resources.openRawResource(R.raw.wallethsm)
            .use { inputStream ->
                keyStore.load(inputStream, password)
            }
        val privateKey = keyStore.getKey(alias, password) as ECPrivateKey
        val publicKey = keyStore.getCertificate(alias).publicKey as ECPublicKey
        return KeyPair(publicKey, privateKey)
    }

    private fun getPinStretchPrivateKey(): PrivateKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        val keyAlias = "pinstretchkey"

        if (!keyStore.containsAlias(keyAlias)) {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                keyAlias, KeyProperties.PURPOSE_AGREE_KEY
            ).setAlgorithmParameterSpec(
                ECGenParameterSpec("secp256r1")
            ).build()

            generator.initialize(parameterSpec)
            generator.generateKeyPair()
        }
        return keyStore.getKey(keyAlias, null) as PrivateKey
    }

    private fun createBffRequest(request: String): BffRequest {
        return BffRequest(clientIdentifier, request)
    }

}
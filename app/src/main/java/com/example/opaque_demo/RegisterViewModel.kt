package com.example.opaque_demo

import android.app.Application
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.opaque_demo.network.ConnectionState
import com.example.opaque_demo.network.OpaqueService
import com.example.opaque_demo.network.WsService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import se.digg.wallet.access_mechanism.api.OpaqueClient
import se.digg.wallet.access_mechanism.exception.OpaqueException
import se.digg.wallet.access_mechanism.model.KeyInfo
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import java.io.InputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

class RegisterViewModel(application: Application) : AndroidViewModel(application) {

    // HTTP service — still used for device-state registration (POST /device-states)
    private val httpService = OpaqueService()

    // WebSocket service — used for all service requests after connect
    private val wsService = WsService()

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

    /** Expose WebSocket connection state to the UI */
    val connectionState: StateFlow<ConnectionState> = wsService.connectionState

    private val opaqueApi: OpaqueClient by lazy {
        OpaqueClient(
            getServerPublicKey(),
            getClientKeyPair(),
            getPinStretchPrivateKey(),
            serverIdentifier,
            "RPS-Ops"
        )
    }

    /**
     * Register device state via HTTP POST (unchanged).
     * This endpoint is not available over WebSocket.
     */
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

                val registerState = httpService.registerState(stateRequest)
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
     * Connect to the WebSocket server and perform HPKE mutual authentication.
     */
    fun connectWebSocket() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val serverHpkeKey = loadWsServerPublicKey()
                wsService.connect(
                    clientId = clientIdentifier,
                    clientKeyPair = getClientKeyPair(),
                    serverHpkePublicKey = serverHpkeKey
                )
                _result.value = "WebSocket connected and authenticated"
            } catch (e: Exception) {
                Log.e("OpaqueDemo", "WebSocket connection failed", e)
                _result.value = "WebSocket connection failed: ${e.message}"
            }
        }
    }

    /**
     * Disconnect the WebSocket.
     */
    fun disconnectWebSocket() {
        wsService.disconnect()
        _result.value = "WebSocket disconnected"
    }

    /**
     * Register a pin (123) for the device.
     * Uses WebSocket for service requests.
     */
    fun registerPin() {
        _keys.value = emptyList()
        val code = _authorizationCode.value
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pin = "123"
                val registrationStart = opaqueApi.registrationStart(pin, code!!)

                val registrationResponse = wsService.sendRequest(
                    registrationStart.registrationRequest
                )

                val registerFinish = opaqueApi.registrationFinish(
                    pin,
                    code,
                    registrationResponse,
                    registrationStart.clientRegistration
                )

                val serverFinish = wsService.sendRequest(
                    registerFinish.registrationUpload
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
            } catch (e: Exception) {
                Log.e("OpaqueDemo", "Error registering pin", e)
                _result.value = "Error registering pin: ${e.message}"
            }
        }
    }

    fun createSession() {
        _keys.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pin = "123"
                val loginStart = opaqueApi.loginStart(pin)

                val serverStart = wsService.sendRequest(loginStart.loginRequest)

                val loginFinish = opaqueApi.loginFinish(
                    pin, serverStart, loginStart.clientRegistration
                )

                wsService.sendRequest(loginFinish.loginFinishRequest)

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

            val serverResponse = wsService.sendRequest(createHsmKey)
            val payload = opaqueApi.decryptPayload(serverResponse, sessionKey!!)
            _result.value = payload
        }
    }

    suspend fun listHsmKey(): List<KeyInfo> = withContext(Dispatchers.IO) {
        val createHsmKey =
            // todo better naming. It's not listing, it's creating a request to send
            opaqueApi.listHsmKeys(sessionKey!!, pakeSessionId!!)

        val serverResponse = wsService.sendRequest(createHsmKey)
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

            val serverResponse = wsService.sendRequest(signRequest.request)
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

            val serverResponse = wsService.sendRequest(createHsmKey)
            val payload = opaqueApi.decryptPayload(serverResponse, sessionKey!!)
            _result.value = payload
        }
    }

    // ─── Key Loading ───

    private fun getServerPublicKey(): ECPublicKey {
        val inputStream: InputStream =
            getApplication<Application>().resources.openRawResource(R.raw.serverkey)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(inputStream)
        return certificate.publicKey as ECPublicKey
    }

    /**
     * Load the server's HPKE public key from res/raw/ws_server_key.json (JWK format).
     */
    private fun loadWsServerPublicKey(): ECPublicKey {
        val jsonString = getApplication<Application>().resources
            .openRawResource(R.raw.ws_server_key)
            .bufferedReader()
            .use { it.readText() }

        val jwk = Json.decodeFromString<WsServerJwk>(jsonString)

        require(jwk.kty == "EC" && jwk.crv == "P-256") {
            "Expected EC P-256 JWK, got kty=${jwk.kty} crv=${jwk.crv}"
        }

        // Decode base64url coordinates
        val xBytes = android.util.Base64.decode(jwk.x, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)
        val yBytes = android.util.Base64.decode(jwk.y, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)

        val ecPoint = ECPoint(BigInteger(1, xBytes), BigInteger(1, yBytes))

        // Get P-256 curve params from the client key pair
        val params: ECParameterSpec = (getClientKeyPair().public as ECPublicKey).params
        val pubKeySpec = ECPublicKeySpec(ecPoint, params)
        return KeyFactory.getInstance("EC").generatePublic(pubKeySpec) as ECPublicKey
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

    override fun onCleared() {
        super.onCleared()
        wsService.disconnect()
    }
}

/** Minimal JWK model for parsing the server's HPKE public key. */
@kotlinx.serialization.Serializable
private data class WsServerJwk(
    val kty: String,
    val crv: String,
    val x: String,
    val y: String,
    val kid: String? = null
)

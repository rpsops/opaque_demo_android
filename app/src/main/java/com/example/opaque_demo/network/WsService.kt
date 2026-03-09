package com.example.opaque_demo.network

import android.util.Log
import com.example.opaque_demo.crypto.HpkeClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.encodeToString
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.io.IOException
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.util.UUID
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * WebSocket service for communicating with the wallet-bff-ws server.
 *
 * Handles:
 * - WebSocket connection lifecycle
 * - HPKE mutual authentication handshake (4-step)
 * - Request/response multiplexing via requestId correlation
 * - Async response push from server
 */
class WsService {

    companion object {
        private const val TAG = "WsService"
        private const val WS_URL = "ws://10.0.2.2:8089/r2ps-api/v1/ws"
        private const val AUTH_TIMEOUT_MS = 10_000L
        private const val REQUEST_TIMEOUT_MS = 30_000L
    }

    private val client = OkHttpClient.Builder()
        .pingInterval(30, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS) // No read timeout for WebSocket
        .build()

    private var webSocket: WebSocket? = null
    private var hpkeClient: HpkeClient? = null

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    /**
     * Pending requests awaiting server responses.
     * Key: requestId (client-generated), Value: CompletableDeferred that completes with the result.
     */
    private val pendingRequests = ConcurrentHashMap<String, CompletableDeferred<String>>()

    /**
     * Request IDs whose responses have already been processed.
     * Used to distinguish at-least-once duplicate deliveries from truly unknown request IDs.
     */
    private val consumedRequestIds: MutableSet<String> =
        Collections.newSetFromMap(ConcurrentHashMap())

    /**
     * Channel for auth handshake messages.
     * The WebSocketListener pushes auth-related messages here,
     * and the connect() coroutine reads from it.
     */
    private val authChannel = Channel<WsServerMessage>(Channel.BUFFERED)

    /**
     * Deferred for the WebSocket open event.
     * Completes when onOpen is called, fails on early connection errors.
     */
    private var openDeferred: CompletableDeferred<Unit>? = null

    /**
     * Connect to the WebSocket server and perform HPKE mutual authentication.
     *
     * @param clientId The device's client identifier
     * @param clientKeyPair The device's EC P-256 key pair
     * @param serverHpkePublicKey The server's HPKE public key (for auth)
     * @throws IOException if connection or authentication fails
     * @throws TimeoutCancellationException if auth handshake times out
     */
    suspend fun connect(
        clientId: String,
        clientKeyPair: KeyPair,
        serverHpkePublicKey: ECPublicKey
    ) {
        if (_connectionState.value == ConnectionState.AUTHENTICATED) {
            Log.w(TAG, "Already connected and authenticated")
            return
        }

        _connectionState.value = ConnectionState.CONNECTING
        hpkeClient = HpkeClient(clientKeyPair, serverHpkePublicKey)

        // Open WebSocket
        val request = Request.Builder().url(WS_URL).build()
        val deferred = CompletableDeferred<Unit>()
        openDeferred = deferred

        webSocket = client.newWebSocket(request, WsListener())

        try {
            // Wait for onOpen
            withTimeout(AUTH_TIMEOUT_MS) {
                deferred.await()
            }
        } catch (e: Exception) {
            _connectionState.value = ConnectionState.DISCONNECTED
            throw IOException("WebSocket connection failed: ${e.message}", e)
        }

        // ─── HPKE Authentication Handshake ───
        _connectionState.value = ConnectionState.AUTHENTICATING

        try {
            withTimeout(AUTH_TIMEOUT_MS) {
                // Step 1: Send auth_init
                val authInit = WsAuthInit(clientId = clientId)
                sendMessage(authInit)
                Log.d(TAG, "Sent auth_init for clientId=$clientId")

                // Step 2: Wait for auth_challenge
                val challenge = waitForAuthMessage<WsAuthChallenge>()
                Log.d(TAG, "Received auth_challenge (serverKid=${challenge.serverKid})")

                // Step 3: Process challenge and send auth_response
                val (enc, ciphertext) = hpkeClient!!.handleChallenge(
                    challenge.enc,
                    challenge.ciphertext,
                    challenge.salt
                )
                val authResponse = WsAuthResponse(enc = enc, ciphertext = ciphertext)
                sendMessage(authResponse)
                Log.d(TAG, "Sent auth_response")

                // Step 4: Wait for auth_ok
                val authOk = waitForAuthMessage<WsAuthOk>()
                Log.d(TAG, "Received auth_ok (clientId=${authOk.clientId})")
            }
        } catch (e: Exception) {
            _connectionState.value = ConnectionState.DISCONNECTED
            disconnect()
            throw IOException("HPKE authentication failed: ${e.message}", e)
        }

        _connectionState.value = ConnectionState.AUTHENTICATED
        Log.i(TAG, "WebSocket connected and authenticated")
    }

    /**
     * Send a service request over the WebSocket and wait for the response.
     *
     * @param outerRequestJws The JWS-signed service request
     * @return The result JWS string from the server response
     * @throws IOException if the connection is not authenticated or the request fails
     * @throws TimeoutCancellationException if the response times out
     */
    suspend fun sendRequest(outerRequestJws: String): String {
        if (_connectionState.value != ConnectionState.AUTHENTICATED) {
            throw IOException("WebSocket not authenticated (state=${_connectionState.value})")
        }

        val requestId = UUID.randomUUID().toString()
        val deferred = CompletableDeferred<String>()
        pendingRequests[requestId] = deferred

        try {
            val request = WsRequest(
                requestId = requestId,
                outerRequestJws = outerRequestJws
            )
            sendMessage(request)
            Log.d(TAG, "Sent request (requestId=$requestId)")

            return withTimeout(REQUEST_TIMEOUT_MS) {
                deferred.await()
            }
        } catch (e: Exception) {
            pendingRequests.remove(requestId)
            throw when (e) {
                is IOException -> e
                is TimeoutCancellationException -> IOException("Request timed out (requestId=$requestId)")
                else -> IOException("Request failed: ${e.message}", e)
            }
        }
    }

    /**
     * Disconnect the WebSocket.
     */
    fun disconnect() {
        webSocket?.close(1000, "Client closing")
        webSocket = null
        _connectionState.value = ConnectionState.DISCONNECTED

        // Fail all pending requests
        val error = IOException("WebSocket disconnected")
        for ((_, deferred) in pendingRequests) {
            deferred.completeExceptionally(error)
        }
        pendingRequests.clear()
        consumedRequestIds.clear()

        Log.i(TAG, "WebSocket disconnected")
    }

    // ─── Internal Helpers ───

    private fun sendMessage(message: WsClientMessage) {
        val json = wsJson.encodeToString<WsClientMessage>(message)
        val sent = webSocket?.send(json)
        if (sent != true) {
            throw IOException("Failed to send WebSocket message")
        }
    }

    /**
     * Wait for a specific auth message type from the authChannel.
     * Throws IOException if an auth_error is received instead.
     */
    private suspend inline fun <reified T : WsServerMessage> waitForAuthMessage(): T {
        val msg = authChannel.receive()
        if (msg is WsAuthError) {
            throw IOException("Server auth error: ${msg.message}")
        }
        if (msg !is T) {
            throw IOException("Unexpected auth message: ${msg::class.simpleName}")
        }
        return msg
    }

    // ─── OkHttp WebSocketListener ───

    private inner class WsListener : WebSocketListener() {

        override fun onOpen(webSocket: WebSocket, response: Response) {
            Log.d(TAG, "WebSocket opened")
            openDeferred?.complete(Unit)
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            Log.d(TAG, "Received: $text")

            val message = try {
                wsJson.decodeFromString<WsServerMessage>(text)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse server message: $text", e)
                return
            }

            when (message) {
                // Auth messages -> route to auth channel
                is WsAuthChallenge, is WsAuthOk, is WsAuthError -> {
                    authChannel.trySend(message)
                }

                // Service response -> complete pending request
                is WsResponse -> handleResponse(message)

                // Request-specific error -> fail pending request
                is WsRequestError -> handleRequestError(message)

                // Protocol error -> log
                is WsError -> {
                    Log.e(TAG, "Server protocol error: ${message.message}")
                }
            }
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            Log.d(TAG, "WebSocket closing: code=$code reason=$reason")
            webSocket.close(code, reason)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            Log.i(TAG, "WebSocket closed: code=$code reason=$reason")
            handleDisconnect()
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            Log.e(TAG, "WebSocket failure", t)
            openDeferred?.completeExceptionally(
                IOException("WebSocket connection failed: ${t.message}", t)
            )
            handleDisconnect()
        }
    }

    private fun handleResponse(response: WsResponse) {
        val requestId = response.requestId
        if (requestId == null) {
            Log.w(TAG, "Received response without requestId (correlationId=${response.correlationId})")
            return
        }

        val deferred = pendingRequests.remove(requestId)
        if (deferred == null) {
            if (requestId in consumedRequestIds) {
                Log.d(TAG, "Ignoring duplicate delivery for requestId=$requestId")
            } else {
                Log.w(TAG, "Received response for unknown requestId=$requestId")
            }
            return
        }

        consumedRequestIds.add(requestId)

        when (response.status) {
            "COMPLETE" -> {
                val result = response.result
                if (result != null) {
                    deferred.complete(result)
                } else {
                    deferred.completeExceptionally(
                        IOException("Server returned COMPLETE but no result (requestId=$requestId)")
                    )
                }
            }

            "ERROR" -> {
                val errorMsg = response.error?.message ?: "Unknown error"
                deferred.completeExceptionally(IOException("Server error: $errorMsg"))
            }

            else -> {
                Log.w(TAG, "Unexpected response status: ${response.status}")
                deferred.completeExceptionally(
                    IOException("Unexpected response status: ${response.status}")
                )
            }
        }
    }

    private fun handleRequestError(error: WsRequestError) {
        val deferred = pendingRequests.remove(error.requestId)
        if (deferred != null) {
            deferred.completeExceptionally(IOException("Request error: ${error.message}"))
        } else {
            Log.w(TAG, "Received request_error for unknown requestId=${error.requestId}")
        }
    }

    private fun handleDisconnect() {
        _connectionState.value = ConnectionState.DISCONNECTED
        val error = IOException("WebSocket disconnected")
        for ((_, deferred) in pendingRequests) {
            deferred.completeExceptionally(error)
        }
        pendingRequests.clear()
        consumedRequestIds.clear()
    }
}

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    AUTHENTICATING,
    AUTHENTICATED
}

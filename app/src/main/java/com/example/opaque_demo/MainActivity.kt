package com.example.opaque_demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.opaque_demo.ui.theme.Opaque_demoTheme
import kotlinx.coroutines.launch
import se.digg.wallet.access_mechanism.model.KeyInfo

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Opaque_demoTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Buttons(
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun Buttons(modifier: Modifier = Modifier, viewModel: RegisterViewModel = viewModel()) {
    val result by viewModel.result.collectAsState()
    val keys by viewModel.keys.collectAsState()
    val authorizationCode by viewModel.authorizationCode.collectAsState()
    val scope = rememberCoroutineScope()

    var selectedKeyForAction by remember { mutableStateOf<KeyInfo?>(null) }

    if (selectedKeyForAction != null) {
        AlertDialog(
            onDismissRequest = { selectedKeyForAction = null },
            title = { Text("Select Action") },
            text = { Text("Choose an action for key ${selectedKeyForAction?.publicKey?.keyID}") },
            confirmButton = {
                TextButton(onClick = {
                    selectedKeyForAction?.let { viewModel.sign(it) }
                    selectedKeyForAction = null
                }) {
                    Text("Sign")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    selectedKeyForAction?.let { viewModel.deleteKey(it) }
                    selectedKeyForAction = null
                }) {
                    Text("Delete")
                }
            }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Single container for either result text or interactive key list
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .border(1.dp, Color.Gray)
                .padding(8.dp)
        ) {
            if (keys.isNotEmpty()) {
                Column(modifier = Modifier.fillMaxSize()) {
                    Text(
                        text = "Long press a key for options",
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                    LazyColumn(modifier = Modifier.weight(1f)) {
                        items(keys) { key ->
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .combinedClickable(
                                        onClick = { /* Info */ },
                                        onLongClick = { selectedKeyForAction = key }
                                    )
                                    .padding(vertical = 8.dp)
                            ) {
                                Text(
                                    text = "ID: ${key.publicKey.keyID}",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Text(
                                    text = "Created: ${key.createdAt}",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                HorizontalDivider()
                            }
                        }
                    }
                }
            } else {
                SelectionContainer {
                    Text(
                        text = result ?: "",
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Buttons at the bottom
        Button(
            modifier = Modifier.fillMaxWidth(),
            onClick = { viewModel.registerNewState() }) { Text(text = "Register new state") }
        Button(
            modifier = Modifier.fillMaxWidth(),
            enabled = authorizationCode != null,
            onClick = { viewModel.registerPin() }
        ) {
            Text(text = "Register pin")
        }
        Button(
            modifier = Modifier.fillMaxWidth(),
            onClick = { viewModel.createSession() }
        ) {
            Text(text = "Create session")
        }
        Button(
            modifier = Modifier.fillMaxWidth(),
            onClick = { viewModel.createHsmKey() }
        ) {
            Text(text = "Create HSM key")
        }
        Button(
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                scope.launch {
                    viewModel.listHsmKey()
                }
            }) {
            Text(text = "List HSM keys")
        }
    }
}
package org.shadow6.android.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.shadow6.android.R
import java.util.Base64

/** This adapter can run independently of the bundled native Core processes. */
@Composable
fun VpnControls() {
    val context = LocalContext.current
    val status by Shadow6VpnService.status.collectAsState()
    var host by remember { mutableStateOf("127.0.0.1") }
    var port by remember { mutableStateOf("1088") }
    var key by remember { mutableStateOf("") }
    var sideOne by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var pending by remember { mutableStateOf<Intent?>(null) }
    val active = status.starting || status.running
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val start = pending
        pending = null
        if (result.resultCode == Activity.RESULT_OK && start != null) {
            runCatching { context.startForegroundService(start) }
                .onFailure { error = it.message }
        } else error = context.getString(R.string.vpn_consent_denied)
    }
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.vpn_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.vpn_description), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(when {
                status.starting -> R.string.vpn_starting
                status.running -> R.string.vpn_active
                else -> R.string.stopped
            }))
            OutlinedTextField(host, { host = it.take(45) }, Modifier.fillMaxWidth(),
                enabled = !active && pending == null, label = { Text(stringResource(R.string.vpn_peer)) }, singleLine = true)
            OutlinedTextField(port, { port = it.filter(Char::isDigit).take(5) }, Modifier.fillMaxWidth(),
                enabled = !active && pending == null, label = { Text(stringResource(R.string.port)) }, singleLine = true)
            OutlinedTextField(key, { key = it.take(44) }, Modifier.fillMaxWidth(),
                enabled = !active && pending == null, label = { Text(stringResource(R.string.vpn_key)) },
                visualTransformation = PasswordVisualTransformation(), singleLine = true)
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.vpn_side))
                Switch(sideOne, { sideOne = it }, enabled = !active && pending == null)
            }
            Button(onClick = {
                error = null
                if (active) context.stopService(Intent(context, Shadow6VpnService::class.java))
                else runCatching {
                    val number = port.toIntOrNull()
                    require(number != null && number in 1..65535 && key.length == 44 &&
                        Base64.getDecoder().decode(key).size == 32 && host.isNotBlank()) {
                        context.getString(R.string.vpn_invalid_config)
                    }
                    val start = Intent(context, Shadow6VpnService::class.java).setAction(Shadow6VpnService.ACTION_START)
                        .putExtra(Shadow6VpnService.EXTRA_HOST, host.trim())
                        .putExtra(Shadow6VpnService.EXTRA_PORT, number)
                        .putExtra(Shadow6VpnService.EXTRA_KEY, key)
                        .putExtra(Shadow6VpnService.EXTRA_SIDE, if (sideOne) 1 else 0)
                    val request = VpnService.prepare(context)
                    if (request == null) context.startForegroundService(start)
                    else { pending = start; consent.launch(request) }
                    key = "" // never persist session keys in UI preferences
                }.onFailure { error = it.message ?: context.getString(R.string.vpn_invalid_config) }
            }, enabled = pending == null, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(if (active) R.string.vpn_stop else R.string.vpn_start))
            }
            (error ?: status.error)?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        }
    }
}

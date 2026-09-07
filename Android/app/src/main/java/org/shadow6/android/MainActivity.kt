@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package org.shadow6.android

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.ShoppingCart
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.shadow6.android.ai.OpenAiCompatibleClient
import org.shadow6.android.core.AccessMode
import org.shadow6.android.core.CoreEngine
import org.shadow6.android.core.CoreController
import org.shadow6.android.core.CoreProfile
import org.shadow6.android.core.CoreRole
import org.shadow6.android.core.CoreRuntime
import org.shadow6.android.core.CoreService
import org.shadow6.android.core.CoreStatus
import org.shadow6.android.gate.GateController
import org.shadow6.android.gate.GateProfile
import org.shadow6.android.packages.RemoteRepository
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        val language = newBase.getSharedPreferences(UI_PREFERENCES, MODE_PRIVATE)
            .getString(LANGUAGE_KEY, LANGUAGE_SYSTEM) ?: LANGUAGE_SYSTEM
        if (language == LANGUAGE_SYSTEM) {
            super.attachBaseContext(newBase)
            return
        }
        val locale = Locale.forLanguageTag(language)
        val configuration = Configuration(newBase.resources.configuration).apply {
            setLocale(locale)
            setLayoutDirection(locale)
        }
        super.attachBaseContext(newBase.createConfigurationContext(configuration))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { Shadow6App() }
    }

    companion object {
        const val UI_PREFERENCES = "shadow6-ui"
        const val LANGUAGE_KEY = "language"
        const val LANGUAGE_SYSTEM = "system"
    }
}

private enum class Destination(val label: Int, val icon: ImageVector) {
    OVERVIEW(R.string.overview, Icons.Outlined.Home),
    CHAT(R.string.shadow_chat, Icons.Outlined.Email),
    SEARCH(R.string.search, Icons.Outlined.Search),
    PACKAGES(R.string.packages, Icons.Outlined.ShoppingCart),
    GAMES(R.string.games, Icons.Outlined.Star),
    AI(R.string.ai, Icons.Outlined.Info),
    SETTINGS(R.string.settings, Icons.Outlined.Settings),
}

private val ShadowLightColors = lightColorScheme(
    primary = Color(0xFF075985),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFCFFAFE),
    onPrimaryContainer = Color(0xFF083344),
    secondary = Color(0xFF6D28D9),
    secondaryContainer = Color(0xFFEDE9FE),
    surface = Color(0xFFF8FAFC),
    surfaceVariant = Color(0xFFE2E8F0),
    background = Color(0xFFF8FAFC),
    error = Color(0xFFB42318),
)

private val ShadowDarkColors = darkColorScheme(
    primary = Color(0xFF67E8F9),
    onPrimary = Color(0xFF083344),
    primaryContainer = Color(0xFF164E63),
    secondary = Color(0xFFC4B5FD),
    secondaryContainer = Color(0xFF4C1D95),
    surface = Color(0xFF0F172A),
    surfaceVariant = Color(0xFF1E293B),
    background = Color(0xFF020617),
)

@Composable
fun Shadow6App() {
    val context = LocalContext.current
    val runtime = remember { CoreController.runtime(context.applicationContext) }
    var destination by remember { mutableStateOf(Destination.OVERVIEW) }
    var status by remember { mutableStateOf(runtime.status()) }
    val visible = remember {
        Destination.entries.filter {
            when (it) {
                Destination.CHAT -> BuildConfig.INCLUDE_CHAT
                Destination.PACKAGES -> BuildConfig.INCLUDE_PACKAGES
                Destination.GAMES -> BuildConfig.INCLUDE_GAMES
                Destination.AI -> BuildConfig.INCLUDE_AI
                else -> true
            }
        }
    }
    val mainDestinations = listOf(Destination.OVERVIEW, Destination.AI, Destination.SEARCH, Destination.PACKAGES, Destination.SETTINGS)
        .filter { it in visible }

    LaunchedEffect(runtime) {
        while (true) {
            status = withContext(Dispatchers.IO) { runtime.status() }
            delay(750)
        }
    }

    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) ShadowDarkColors else ShadowLightColors) {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            topBar = {
                TopAppBar(
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Image(
                                painterResource(R.drawable.shadow6_app_icon),
                                contentDescription = null,
                                modifier = Modifier.size(36.dp),
                            )
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text("Shadow6", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                                Text(
                                    stringResource(destination.label),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    },
                    actions = {
                        CoreStatusPill(status)
                        QuickLanguageButton()
                    },
                )
            },
            bottomBar = {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                    mainDestinations.forEach { target ->
                        NavigationBarItem(
                            selected = target == destination,
                            onClick = { destination = target },
                            icon = { Icon(target.icon, contentDescription = null) },
                            label = { Text(stringResource(target.label), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        )
                    }
                }
            },
        ) { padding ->
            Surface(Modifier.fillMaxSize().padding(padding)) {
                when (destination) {
                    Destination.OVERVIEW -> OverviewScreen(runtime, status) { status = it }
                    Destination.CHAT -> ChatScreen()
                    Destination.SEARCH -> SearchScreen(visible) { destination = it }
                    Destination.PACKAGES -> PackagesScreen()
                    Destination.GAMES -> GuessGameScreen()
                    Destination.AI -> AiSettingsScreen()
                    Destination.SETTINGS -> SettingsScreen()
                }
            }
        }
    }
}

@Composable
private fun CoreStatusPill(status: CoreStatus) {
    val background = if (status.running) Color(0xFFDCFCE7) else MaterialTheme.colorScheme.surfaceVariant
    val foreground = if (status.running) Color(0xFF166534) else MaterialTheme.colorScheme.onSurfaceVariant
    Surface(color = background, shape = RoundedCornerShape(99.dp)) {
        Row(
            modifier = Modifier.padding(horizontal = 9.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(foreground))
            Spacer(Modifier.width(6.dp))
            Text(
                if (status.running) status.port.toString() else stringResource(R.string.stopped),
                style = MaterialTheme.typography.labelMedium,
                color = foreground,
            )
        }
    }
}

@Composable
private fun QuickLanguageButton() {
    val context = LocalContext.current
    val currentIsChinese = context.resources.configuration.locales[0].language == Locale.CHINESE.language
    TextButton(onClick = {
        val tag = if (currentIsChinese) "en" else "zh-CN"
        context.getSharedPreferences(MainActivity.UI_PREFERENCES, Context.MODE_PRIVATE)
            .edit().putString(MainActivity.LANGUAGE_KEY, tag).apply()
        (context as? ComponentActivity)?.recreate()
    }) { Text(if (currentIsChinese) "EN" else "中", fontWeight = FontWeight.Bold) }
}

@Composable
private fun Page(title: String, subtitle: String? = null, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        if (subtitle != null) Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant)
        content()
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun OverviewScreen(runtime: CoreRuntime, status: CoreStatus, onStatusChange: (CoreStatus) -> Unit) {
    val context = LocalContext.current
    val preferences = remember { context.getSharedPreferences("core", Context.MODE_PRIVATE) }
    val gateRuntime = remember { GateController.runtime(context) }
    val defaultEngine = CoreEngine.entries.firstOrNull { runtime.available(it) } ?: CoreEngine.GO
    var engine by remember { mutableStateOf(runCatching { CoreEngine.valueOf(preferences.getString("engine", defaultEngine.name)!!) }.getOrDefault(defaultEngine)) }
    var mode by remember { mutableStateOf(runCatching { AccessMode.valueOf(preferences.getString("mode", AccessMode.NON_ROOT.name)!!) }.getOrDefault(AccessMode.NON_ROOT)) }
    var role by remember { mutableStateOf(runCatching { CoreRole.valueOf(preferences.getString("role", CoreRole.BROKER.name)!!) }.getOrDefault(CoreRole.BROKER)) }
    var host by remember { mutableStateOf(preferences.getString("host", "127.0.0.1") ?: "127.0.0.1") }
    var portText by remember { mutableStateOf(preferences.getInt("port", 4433).toString()) }
    var identityId by remember { mutableStateOf(preferences.getString("identity", "android-1") ?: "android-1") }
    var privateKey by remember { mutableStateOf(preferences.getString("private_key", "") ?: "") }
    var publicKey by remember { mutableStateOf(preferences.getString("public_key", "") ?: "") }
    var brokerAddresses by remember { mutableStateOf(preferences.getString("broker_addresses", "") ?: "") }
    var brokerPublicKey by remember { mutableStateOf(preferences.getString("broker_public_key", "") ?: "") }
    var targetPort by remember { mutableStateOf(preferences.getInt("target_port", 22).toString()) }
    var autoClose by remember { mutableStateOf(preferences.getInt("auto_close", 7200).toString()) }
    var localDiscovery by remember { mutableStateOf(preferences.getBoolean("local_discovery", false)) }
    var targetAgent by remember { mutableStateOf(preferences.getString("target_agent", "agent-1") ?: "agent-1") }
    var agentPublicKey by remember { mutableStateOf(preferences.getString("agent_public_key", "") ?: "") }
    var webhook by remember { mutableStateOf(preferences.getString("webhook", "") ?: "") }
    var stealth by remember { mutableStateOf(preferences.getBoolean("stealth", false)) }
    var agentsJson by remember { mutableStateOf(preferences.getString("agents_json", "[]") ?: "[]") }
    var clientsJson by remember { mutableStateOf(preferences.getString("clients_json", "[]") ?: "[]") }
    var clientKeysJson by remember { mutableStateOf(preferences.getString("client_keys_json", "{}") ?: "{}") }
    var sni by remember { mutableStateOf(preferences.getString("sni", "") ?: "") }
    var alpn by remember { mutableStateOf(preferences.getString("alpn", "") ?: "") }
    var advanced by remember { mutableStateOf(false) }
    var gateEnabled by remember { mutableStateOf(preferences.getBoolean("gate_enabled", false)) }
    var gateRemoteHost by remember { mutableStateOf(preferences.getString("gate_remote_host", "") ?: "") }
    var gateLocalPort by remember { mutableStateOf(preferences.getInt("gate_local_port", 1086).toString()) }
    var gateExpected by remember { mutableStateOf(false) }
    var gateFailureReported by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    val rootAvailable by produceState<Boolean?>(initialValue = null, runtime) {
        value = withContext(Dispatchers.IO) { runtime.rootAvailable() }
    }
    LaunchedEffect(runtime, gateEnabled, gateExpected, status.running) {
        while (true) {
            if (gateEnabled && gateExpected && status.running && !gateFailureReported) {
                val gateAlive = withContext(Dispatchers.IO) { gateRuntime.running() }
                if (!gateAlive) {
                    val stopped = withContext(Dispatchers.IO) { runtime.stop() }
                    gateFailureReported = true
                    gateExpected = false
                    onStatusChange(stopped.copy(detail = "Gate crashed unexpectedly"))
                }
            }
            delay(500)
        }
    }
    fun profile() = CoreProfile(
        role, host.trim(), portText.toIntOrNull() ?: 0, identityId.trim(), privateKey.trim(), publicKey.trim(),
        brokerAddresses.trim(), brokerPublicKey.trim(), targetPort.toIntOrNull() ?: 0,
        autoClose.toIntOrNull() ?: 0, localDiscovery, targetAgent.trim(), agentPublicKey.trim(), webhook.trim(),
        stealth, agentsJson.trim(), clientsJson.trim(), clientKeysJson.trim(), sni.trim(), alpn.trim(),
    )

    fun persist() {
        preferences.edit().putString("engine", engine.name).putString("mode", mode.name).putString("role", role.name)
            .putString("host", host).putInt("port", portText.toIntOrNull() ?: 0).putString("identity", identityId)
            .putString("private_key", privateKey).putString("public_key", publicKey).putString("broker_addresses", brokerAddresses)
            .putString("broker_public_key", brokerPublicKey).putInt("target_port", targetPort.toIntOrNull() ?: 0)
            .putInt("auto_close", autoClose.toIntOrNull() ?: 0).putBoolean("local_discovery", localDiscovery)
            .putString("target_agent", targetAgent).putString("agent_public_key", agentPublicKey).putString("webhook", webhook)
            .putBoolean("stealth", stealth).putString("agents_json", agentsJson).putString("clients_json", clientsJson)
            .putString("client_keys_json", clientKeysJson).putString("sni", sni).putString("alpn", alpn).apply()
        preferences.edit().putBoolean("gate_enabled", gateEnabled).putString("gate_remote_host", gateRemoteHost)
            .putInt("gate_local_port", gateLocalPort.toIntOrNull() ?: 0).apply()
    }

    Page(stringResource(R.string.core_control), stringResource(R.string.core_control_subtitle)) {
        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(28.dp)).background(
                Brush.linearGradient(listOf(Color(0xFF082F49), Color(0xFF312E81))),
            ).padding(22.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Image(painterResource(R.drawable.shadow6_app_icon), null, Modifier.size(72.dp))
                    Spacer(Modifier.width(16.dp))
                    Column {
                        Text(
                            if (status.running) stringResource(R.string.core_online) else stringResource(R.string.core_offline),
                            color = Color.White,
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(status.endpoint, color = Color(0xFFCFFAFE), style = MaterialTheme.typography.titleMedium, maxLines = 2)
                    }
                }
                HorizontalDivider(color = Color.White.copy(alpha = 0.18f))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    StatusValue(stringResource(R.string.engine), status.engine.name, Color.White)
                    StatusValue(stringResource(R.string.access_mode), if (status.mode == AccessMode.ROOT) "ROOT" else "SANDBOX", Color.White)
                    StatusValue(stringResource(R.string.role), status.role.name, Color.White)
                }
            }
        }

        SectionLabel(stringResource(R.string.core_engine))
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            val engines = CoreEngine.entries.filter { runtime.available(it) }
            engines.forEachIndexed { index, value ->
                SegmentedButton(
                    selected = value == engine,
                    onClick = {
                        engine = value
                        preferences.edit().putString("engine", value.name).apply()
                    },
                    shape = SegmentedButtonDefaults.itemShape(index, engines.size),
                    enabled = !status.running && !busy,
                ) { Text(when (value) {
                    CoreEngine.GO -> stringResource(R.string.go_core)
                    CoreEngine.RUST -> stringResource(R.string.rust_core)
                    CoreEngine.D -> "D Core"
                    CoreEngine.NIM -> "Nim Core"
                }) }
            }
        }

        SectionLabel(stringResource(R.string.access_mode))
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            AccessMode.entries.forEachIndexed { index, value ->
                SegmentedButton(
                    selected = value == mode,
                    onClick = {
                        mode = value
                        preferences.edit().putString("mode", value.name).apply()
                    },
                    shape = SegmentedButtonDefaults.itemShape(index, AccessMode.entries.size),
                    enabled = !status.running && !busy && (value != AccessMode.ROOT || rootAvailable == true),
                ) { Text(if (value == AccessMode.ROOT) stringResource(R.string.root) else stringResource(R.string.non_root)) }
            }
        }
        if (rootAvailable == false) Text(stringResource(R.string.root_unavailable), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        SectionLabel(stringResource(R.string.role))
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            CoreRole.entries.forEachIndexed { index, value ->
                SegmentedButton(role == value, { role = value }, SegmentedButtonDefaults.itemShape(index, CoreRole.entries.size), enabled = !status.running && !busy) {
                    Text(value.name.lowercase().replaceFirstChar(Char::uppercase))
                }
            }
        }

        SectionLabel(stringResource(R.string.identity))
        if (role != CoreRole.BROKER) ConfigField(identityId, { identityId = it.take(64) }, stringResource(R.string.node_id), !status.running && !busy)
        ConfigField(privateKey, { privateKey = it.filter(Char::isLetterOrDigit).take(128) }, stringResource(R.string.private_key), !status.running && !busy, password = true)
        ConfigField(publicKey, { publicKey = it.filter(Char::isLetterOrDigit).take(64) }, stringResource(R.string.public_key), !status.running && !busy)
        Button(onClick = {
            busy = true; error = ""
            scope.launch {
                runCatching { withContext(Dispatchers.IO) { runtime.generateIdentity(engine) } }
                    .onSuccess { privateKey = it.privateKey; publicKey = it.publicKey; persist() }
                    .onFailure { error = it.message ?: "Key generation failed" }
                busy = false
            }
        }, enabled = !status.running && !busy, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.generate_identity)) }

        when (role) {
            CoreRole.BROKER -> {
                SectionLabel(stringResource(R.string.listen_endpoint))
                ConfigField(host, { host = it.take(253) }, stringResource(R.string.listen_host), !status.running && !busy)
                NumberField(portText, { portText = it }, stringResource(R.string.port), !status.running && !busy)
                ConfigField(webhook, { webhook = it.take(2048) }, stringResource(R.string.webhook_url), !status.running && !busy)
                SwitchRow(stringResource(R.string.stealth_mode), stealth, { stealth = it }, !status.running && !busy)
            }
            CoreRole.AGENT, CoreRole.CLIENT -> {
                SectionLabel(stringResource(R.string.broker_connection))
                ConfigField(brokerAddresses, { brokerAddresses = it.take(8192) }, stringResource(R.string.broker_addresses), !status.running && !busy, minLines = 2)
                ConfigField(brokerPublicKey, { brokerPublicKey = it.filter(Char::isLetterOrDigit).take(64) }, stringResource(R.string.broker_public_key), !status.running && !busy)
                SwitchRow(stringResource(R.string.local_discovery), localDiscovery, { localDiscovery = it }, !status.running && !busy)
                if (role == CoreRole.AGENT) {
                    NumberField(targetPort, { targetPort = it }, stringResource(R.string.target_port), !status.running && !busy)
                    NumberField(autoClose, { autoClose = it }, stringResource(R.string.auto_close), !status.running && !busy)
                } else {
                    ConfigField(targetAgent, { targetAgent = it.take(64) }, stringResource(R.string.target_agent), !status.running && !busy)
                    ConfigField(agentPublicKey, { agentPublicKey = it.filter(Char::isLetterOrDigit).take(64) }, stringResource(R.string.agent_public_key), !status.running && !busy)
                }
                Text("${stringResource(R.string.transport)}: ${engine.transport.uppercase(java.util.Locale.ROOT)}", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        TextButton(onClick = { advanced = !advanced }, modifier = Modifier.fillMaxWidth()) {
            Text(if (advanced) stringResource(R.string.hide_advanced) else stringResource(R.string.show_advanced))
        }
        AnimatedVisibility(advanced) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (role == CoreRole.BROKER) {
                    ConfigField(agentsJson, { agentsJson = it.take(65_536) }, stringResource(R.string.agent_acl_json), !status.running && !busy, minLines = 4)
                    ConfigField(clientsJson, { clientsJson = it.take(65_536) }, stringResource(R.string.client_acl_json), !status.running && !busy, minLines = 4)
                }
                if (role == CoreRole.AGENT) ConfigField(clientKeysJson, { clientKeysJson = it.take(65_536) }, stringResource(R.string.client_keys_json), !status.running && !busy, minLines = 4)
                if (engine == CoreEngine.RUST && role != CoreRole.BROKER) {
                    ConfigField(sni, { sni = it.take(253) }, "SNI", !status.running && !busy)
                    ConfigField(alpn, { alpn = it.take(255) }, "ALPN", !status.running && !busy)
                }
                if (BuildConfig.INCLUDE_GATE && role != CoreRole.BROKER) {
                    SectionLabel(stringResource(R.string.gate_title))
                    SwitchRow(stringResource(R.string.gate_enable), gateEnabled, { gateEnabled = it }, !status.running && !busy)
                    if (gateEnabled) {
                        ConfigField(gateRemoteHost, { gateRemoteHost = it.take(45) }, stringResource(R.string.gate_remote_host), !status.running && !busy)
                        NumberField(gateLocalPort, { gateLocalPort = it }, stringResource(R.string.gate_local_port), !status.running && !busy)
                        Text(stringResource(R.string.gate_mtd_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }

        Button(
            onClick = {
                error = ""
                busy = true
                scope.launch {
                    val result = runCatching {
                        withContext(Dispatchers.IO) {
                            if (status.running) {
                                gateExpected = false
                                gateRuntime.stop()
                                val stopped = runtime.stop()
                                context.stopService(Intent(context, CoreService::class.java))
                                stopped
                            } else {
                                val selected = profile()
                                selected.toJson(engine)
                                persist()
                                context.startForegroundService(Intent(context, CoreService::class.java).setAction(CoreService.ACTION_KEEP_ALIVE))
                                runtime.start(engine, mode, selected)
                                    .also {
                                        if (gateEnabled) {
                                            gateRuntime.start(GateProfile(true, gateLocalPort.toIntOrNull() ?: 0, gateRemoteHost.trim(), "127.0.0.1:4433", privateKey.trim(), brokerPublicKey.trim(), "unconditional"))
                                            gateFailureReported = false
                                            gateExpected = true
                                        }
                                    }
                            }
                        }
                    }
                    result.onSuccess(onStatusChange).onFailure { error = it.message ?: "Core error" }
                    busy = false
                }
            },
            modifier = Modifier.fillMaxWidth().height(54.dp),
            enabled = !busy,
            colors = if (status.running) ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error) else ButtonDefaults.buttonColors(),
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
            else Icon(if (status.running) Icons.Outlined.Close else Icons.Outlined.PlayArrow, null)
            Spacer(Modifier.width(8.dp))
            Text(if (status.running) stringResource(R.string.stop_core) else stringResource(R.string.start_core), fontWeight = FontWeight.Bold)
        }
        if (error.isNotBlank()) Text(error, color = MaterialTheme.colorScheme.error)
        if (status.detail.isNotBlank()) Text(status.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (status.running && status.role == CoreRole.CLIENT) {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.local_proxy), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        if (status.port > 0) status.endpoint else stringResource(R.string.waiting_for_proxy),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Button(
                        onClick = {
                            error = ""
                            runCatching {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("http://${status.endpoint}/")))
                            }.onFailure { error = context.getString(R.string.browser_unavailable) }
                        },
                        modifier = Modifier.fillMaxWidth().height(52.dp),
                        enabled = status.port > 0,
                    ) { Text(stringResource(R.string.open_local_proxy)) }
                }
            }
        }

        ElevatedCard(Modifier.fillMaxWidth(), colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.Info, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(12.dp))
                Text(stringResource(R.string.config_security_note), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun StatusValue(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = color, fontWeight = FontWeight.Bold)
        Text(label, color = color.copy(alpha = 0.68f), style = MaterialTheme.typography.labelSmall)
    }
}

@Composable private fun SectionLabel(value: String) = Text(value, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)

@Composable
private fun ConfigField(value: String, onChange: (String) -> Unit, label: String, enabled: Boolean,
                        password: Boolean = false, minLines: Int = 1) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
        label = { Text(label) },
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        minLines = minLines,
        maxLines = if (minLines == 1) 1 else 8,
    )
}

@Composable
private fun NumberField(value: String, onChange: (String) -> Unit, label: String, enabled: Boolean) =
    OutlinedTextField(value, { onChange(it.filter(Char::isDigit).take(5)) }, Modifier.fillMaxWidth(), enabled = enabled,
        label = { Text(label) }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), singleLine = true)

@Composable
private fun SwitchRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit, enabled: Boolean) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth().clickable(enabled = enabled) { onChange(!checked) }.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label)
            Switch(checked, onChange, enabled = enabled)
        }
    }
}

private data class SearchEntry(val title: String, val detail: String, val destination: Destination)

@Composable
private fun SearchScreen(destinations: List<Destination>, onNavigate: (Destination) -> Unit) {
    var query by remember { mutableStateOf("") }
    val entries = destinations.map { destination ->
        val detail = when (destination) {
            Destination.OVERVIEW -> stringResource(R.string.search_core_detail)
            Destination.CHAT -> stringResource(R.string.search_chat_detail)
            Destination.SEARCH -> stringResource(R.string.search_search_detail)
            Destination.PACKAGES -> stringResource(R.string.search_packages_detail)
            Destination.GAMES -> stringResource(R.string.search_games_detail)
            Destination.AI -> stringResource(R.string.search_ai_detail)
            Destination.SETTINGS -> stringResource(R.string.search_settings_detail)
        }
        SearchEntry(stringResource(destination.label), detail, destination)
    }
    val filtered = entries.filter { query.isBlank() || it.title.contains(query, true) || it.detail.contains(query, true) }

    Page(stringResource(R.string.search), stringResource(R.string.search_subtitle)) {
        OutlinedTextField(
            value = query,
            onValueChange = { query = it.take(256) },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.search_hint)) },
            leadingIcon = { Icon(Icons.Outlined.Search, null) },
            trailingIcon = {
                if (query.isNotEmpty()) IconButton(onClick = { query = "" }) {
                    Icon(Icons.Outlined.Close, stringResource(R.string.clear_search))
                }
            },
            singleLine = true,
        )
        Text(
            if (query.isBlank()) stringResource(R.string.all_search_results) else stringResource(R.string.result_count, filtered.size),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (filtered.isEmpty()) {
            ElevatedCard(Modifier.fillMaxWidth()) { Text(stringResource(R.string.no_results), Modifier.padding(24.dp)) }
        } else {
            filtered.forEach { entry ->
                ElevatedCard(onClick = { onNavigate(entry.destination) }, modifier = Modifier.fillMaxWidth()) {
                    ListItem(
                        headlineContent = { Text(entry.title, fontWeight = FontWeight.SemiBold) },
                        supportingContent = { Text(entry.detail) },
                        leadingContent = { Icon(entry.destination.icon, null, tint = MaterialTheme.colorScheme.primary) },
                        trailingContent = { Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null) },
                    )
                }
            }
        }
    }
}

@Composable
private fun PackagesScreen() {
    val context=LocalContext.current;val preferences=remember{context.getSharedPreferences("package-sources",Context.MODE_PRIVATE)}
    val scope=rememberCoroutineScope();var busy by remember{mutableStateOf(false)};var source by remember{mutableStateOf(preferences.getString("remote_source","")?:"")};var sourceKey by remember{mutableStateOf(preferences.getString("remote_source_key","")?:"")};var notice by remember{mutableStateOf("")}
    Page(stringResource(R.string.packages), stringResource(R.string.packages_subtitle)) {
        SectionLabel(stringResource(R.string.remote_repository))
        ConfigField(source,{source=it.take(2048)},stringResource(R.string.repository_https_url),true)
        ConfigField(sourceKey,{sourceKey=it.filter(Char::isLetterOrDigit).take(64)},stringResource(R.string.repository_public_key),!busy,password=true)
        Button(onClick={busy=true;scope.launch{runCatching{withContext(Dispatchers.IO){RemoteRepository.fetchAndVerify(source.trim(),sourceKey.trim())}}.onSuccess{preferences.edit().putString("remote_source",source.trim()).putString("remote_source_key",sourceKey.trim()).apply();notice=context.getString(R.string.repository_saved)}.onFailure{notice=it.message?:"Invalid repository"};busy=false}},Modifier.fillMaxWidth(),enabled=source.isNotBlank()&&sourceKey.length==64&&!busy){if(busy)CircularProgressIndicator(Modifier.size(22.dp),strokeWidth=2.dp) else Text(stringResource(R.string.connect_repository))}
        if(notice.isNotBlank())Text(notice,style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun FeatureRows(values: List<Pair<String, String>>) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        values.forEachIndexed { index, value ->
            ListItem(
                headlineContent = { Text(value.first, fontWeight = FontWeight.Medium) },
                supportingContent = { Text(value.second) },
                leadingContent = { Icon(Icons.Outlined.CheckCircle, null, tint = MaterialTheme.colorScheme.primary) },
            )
            if (index != values.lastIndex) HorizontalDivider(Modifier.padding(horizontal = 16.dp))
        }
    }
}

@Composable
private fun ChatScreen() {
    var text by remember { mutableStateOf("") }
    val messages = remember { mutableStateListOf<String>() }
    Page(stringResource(R.string.shadow_chat), stringResource(R.string.chat_subtitle)) {
        if (messages.isEmpty()) Text(stringResource(R.string.chat_empty), color = MaterialTheme.colorScheme.onSurfaceVariant)
        messages.forEach { message ->
            ElevatedCard(Modifier.fillMaxWidth()) { Text(message, Modifier.padding(16.dp)) }
        }
        OutlinedTextField(
            text,
            { if (it.length <= 4096) text = it },
            Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.message)) },
            minLines = 3,
        )
        Button({
            if (text.isNotBlank()) {
                if (messages.size >= 100) messages.removeAt(0)
                messages += text.trim()
                text = ""
            }
        }, Modifier.fillMaxWidth(), enabled = text.isNotBlank()) { Text(stringResource(R.string.send)) }
    }
}

@Composable
private fun GuessGameScreen() {
    var secret by remember { mutableIntStateOf((1..20).random()) }
    var guess by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    Page(stringResource(R.string.guess_game), stringResource(R.string.game_subtitle)) {
        OutlinedTextField(
            guess,
            { guess = it.filter(Char::isDigit).take(2) },
            Modifier.fillMaxWidth(),
            label = { Text("1–20") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )
        Button({
            val number = guess.toIntOrNull()
            result = when {
                number == null -> "1–20"
                number == secret -> "✓ $secret"
                number < secret -> "↑"
                else -> "↓"
            }
        }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.send)) }
        if (result.isNotBlank()) Text(result, style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Bold)
        TextButton({ secret = (1..20).random(); result = ""; guess = "" }) { Text(stringResource(R.string.new_game)) }
    }
}

@Composable
private fun AiSettingsScreen() {
    val context = LocalContext.current
    val client = remember { OpenAiCompatibleClient(context) }
    val preferences = remember { context.getSharedPreferences("ai-ui", Context.MODE_PRIVATE) }
    val scope = rememberCoroutineScope()
    var endpoint by remember { mutableStateOf(preferences.getString("endpoint", "https://api.openai.com") ?: "https://api.openai.com") }
    var model by remember { mutableStateOf(preferences.getString("model", "gpt-5.6") ?: "gpt-5.6") }
    var mcpUrl by remember { mutableStateOf(preferences.getString("mcp", "") ?: "") }
    var key by remember { mutableStateOf("") }
    var prompt by remember { mutableStateOf("") }
    var previousId by remember { mutableStateOf<String?>(null) }
    var settingsVisible by remember { mutableStateOf(!client.hasApiKey()) }
    var notice by remember { mutableStateOf("") }
    val messages = remember { mutableStateListOf<Pair<Boolean, String>>() }
    var busy by remember { mutableStateOf(false) }
    Page(stringResource(R.string.ai), stringResource(R.string.ai_subtitle)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            AssistChip(onClick = { settingsVisible = !settingsVisible }, label = { Text(stringResource(R.string.ai_connection)) })
            TextButton(onClick = { messages.clear(); previousId = null; notice = "" }) { Text(stringResource(R.string.new_chat)) }
        }
        AnimatedVisibility(settingsVisible) {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    ConfigField(endpoint, { endpoint = it.take(2048) }, stringResource(R.string.ai_endpoint), !busy)
                    ConfigField(model, { model = it.take(128) }, stringResource(R.string.model), !busy)
                    ConfigField(mcpUrl, { mcpUrl = it.take(2048) }, stringResource(R.string.mcp_endpoint), !busy)
                    ConfigField(key, { key = it.take(4096) }, stringResource(R.string.api_key), !busy, password = true)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button({
                            notice = runCatching {
                                if (key.isNotBlank()) client.saveApiKey(key, endpoint)
                                preferences.edit().putString("endpoint", endpoint).putString("model", model).putString("mcp", mcpUrl).apply()
                                key = ""; context.getString(R.string.ai_saved)
                            }.getOrElse { it.message ?: "Error" }
                        }, enabled = key.isNotBlank() || client.hasApiKey()) { Text(stringResource(R.string.save)) }
                        TextButton({ client.clearApiKey(); notice = context.getString(R.string.key_cleared) }) { Text(stringResource(R.string.clear_key)) }
                    }
                    Text(stringResource(R.string.mcp_approval_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        if (messages.isEmpty()) ElevatedCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.ai_empty), Modifier.padding(20.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        messages.forEach { message ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = if (message.first) Arrangement.End else Arrangement.Start) {
                Surface(
                    color = if (message.first) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                    shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth(0.88f),
                ) { Text(message.second, Modifier.padding(14.dp)) }
            }
        }
        OutlinedTextField(prompt, { prompt = it.take(65_536) }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.message)) }, minLines = 4)
        Button({
            val sent = prompt.trim()
            messages += true to sent
            prompt = ""
            busy = true
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        client.respond(endpoint, model, sent, previousId, mcpUrl) { name, args -> executeMobileTool(context, name, args) }
                    }
                }.onSuccess { turn ->
                    previousId = turn.responseId
                    messages += false to turn.text
                    notice = if (turn.toolEvents.isEmpty()) "" else context.getString(R.string.tools_used, turn.toolEvents.joinToString())
                    while (messages.size > 40) messages.removeAt(0)
                }.onFailure { messages += false to (it.message ?: "AI error") }
                busy = false
            }
        }, Modifier.fillMaxWidth(), enabled = prompt.isNotBlank() && !busy) {
            if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
            else Text(stringResource(R.string.send))
        }
        if (notice.isNotBlank()) Text(notice, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
        Text(stringResource(R.string.tool_bridge), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun executeMobileTool(context: Context, name: String, arguments: org.json.JSONObject): org.json.JSONObject {
    // Legacy Public6 tool identifiers are intentionally unsupported on Android.
    @Suppress("UNUSED_VARIABLE") val removedPublic6Tool = "shadow6_public6_profile"
    require(arguments.length() == 0) { "This read-only tool accepts no arguments" }
    val status = CoreController.runtime(context).status()
    return when (name) {
        "shadow6_core_status" -> org.json.JSONObject().put("running", status.running).put("engine", status.engine.name.lowercase())
            .put("role", status.role.name.lowercase()).put("access", status.mode.name.lowercase()).put("endpoint", status.endpoint).put("detail", status.detail.take(1024))
        "shadow6_config_summary" -> {
            val prefs = context.getSharedPreferences("core", Context.MODE_PRIVATE)
            org.json.JSONObject().put("role", prefs.getString("role", "BROKER")?.lowercase())
                .put("engine", prefs.getString("engine", "GO")?.lowercase()).put("listen_host", prefs.getString("host", "127.0.0.1"))
                .put("listen_port", prefs.getInt("port", 4433)).put("identity", prefs.getString("identity", "android-1"))
                .put("local_discovery", prefs.getBoolean("local_discovery", false)).put("secrets", "redacted")
        }
        "shadow6_modules" -> org.json.JSONObject().put("go_core", BuildConfig.INCLUDE_GO_CORE)
            .put("rust_core", BuildConfig.INCLUDE_RUST_CORE).put("d_core", BuildConfig.INCLUDE_D_CORE)
            .put("nim_core", BuildConfig.INCLUDE_NIM_CORE)
            .put("shadow_chat", BuildConfig.INCLUDE_CHAT).put("packages", BuildConfig.INCLUDE_PACKAGES).put("games", BuildConfig.INCLUDE_GAMES)
            .put("ai", BuildConfig.INCLUDE_AI).put("mcp", true)
        else -> throw IllegalArgumentException("Unknown or mutating tool")
    }
}

@Composable
private fun SettingsScreen() {
    val context = LocalContext.current
    val preferences = remember { context.getSharedPreferences(MainActivity.UI_PREFERENCES, Context.MODE_PRIVATE) }
    var language by remember { mutableStateOf(preferences.getString(MainActivity.LANGUAGE_KEY, MainActivity.LANGUAGE_SYSTEM) ?: MainActivity.LANGUAGE_SYSTEM) }
    val labels = listOf(
        MainActivity.LANGUAGE_SYSTEM to stringResource(R.string.system_language),
        "en" to "English",
        "zh-CN" to "简体中文",
    )
    val enabled = stringResource(R.string.enabled)
    val excluded = stringResource(R.string.excluded)
    fun state(value: Boolean) = if (value) enabled else excluded

    Page(stringResource(R.string.settings), stringResource(R.string.settings_subtitle)) {
        SectionLabel(stringResource(R.string.language))
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            labels.forEachIndexed { index, item ->
                SegmentedButton(
                    selected = language == item.first,
                    onClick = {
                        language = item.first
                        preferences.edit().putString(MainActivity.LANGUAGE_KEY, item.first).apply()
                        (context as? ComponentActivity)?.recreate()
                    },
                    shape = SegmentedButtonDefaults.itemShape(index, labels.size),
                ) { Text(item.second, maxLines = 1) }
            }
        }
        Text(stringResource(R.string.language_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        SectionLabel(stringResource(R.string.build_modules))
        FeatureRows(
            listOf(
                "Go Core" to state(BuildConfig.INCLUDE_GO_CORE),
                "Rust Core" to state(BuildConfig.INCLUDE_RUST_CORE),
                "Temporary Notepad" to state(BuildConfig.INCLUDE_CHAT),
                stringResource(R.string.packages) to state(BuildConfig.INCLUDE_PACKAGES),
                stringResource(R.string.games) to state(BuildConfig.INCLUDE_GAMES),
                stringResource(R.string.ai) to state(BuildConfig.INCLUDE_AI),
            ),
        )
    }
}

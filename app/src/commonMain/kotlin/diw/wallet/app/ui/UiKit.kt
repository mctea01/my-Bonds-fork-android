package diw.wallet.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * Design tokens taken from the Bonds design system: an indigo accent for everything interactive (green, orange
 * and red are reserved for verdicts), the brand ink for identity only, and verdict colours used as a 0.14 alpha
 * background with a tinted symbol and plain text.
 */
object Tokens {
    val AccentLight = Color(0xFF4B4ED6)
    val AccentDark = Color(0xFF7D7AFF)
    val BrandInk = Color(0xFF0D5B48)
    val Pass = Color(0xFF34C759)
    val Caution = Color(0xFFFF9500)
    val Fail = Color(0xFFFF3B30)
    val ContainerRadius = 16.dp
    val CardRadius = 12.dp
}

@Composable
fun WalletTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) {
        darkColorScheme(
            primary = Tokens.AccentDark,
            onPrimary = Color(0xFF0B0B3B),
            primaryContainer = Color(0xFF2B2C7A),
            onPrimaryContainer = Color(0xFFE2E1FF),
        )
    } else {
        lightColorScheme(
            primary = Tokens.AccentLight,
            onPrimary = Color.White,
            primaryContainer = Color(0xFFE4E3FF),
            onPrimaryContainer = Color(0xFF14146B),
        )
    }
    MaterialTheme(colorScheme = colors, content = content)
}

/** Verdict of a check: pass, caution (partial, unverifiable, offline unknown) or fail. Partial never looks like pass. */
enum class Verdict(val color: Color, val icon: ImageVector) {
    PASS(Tokens.Pass, WalletIcons.Pass),
    CAUTION(Tokens.Caution, WalletIcons.Caution),
    FAIL(Tokens.Fail, WalletIcons.Fail),
}

/** The heaviest element on a result screen: symbol, colour and words together, with its caveats below. */
@Composable
fun VerdictCard(verdict: Verdict, title: String, caveats: List<String> = emptyList()) {
    Column(
        Modifier.fillMaxWidth()
            .background(verdict.color.copy(alpha = 0.14f), RoundedCornerShape(Tokens.ContainerRadius))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(verdict.icon, contentDescription = null, tint = verdict.color, modifier = Modifier.size(36.dp))
            Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        }
        caveats.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
    }
}

/** An empty list: a symbol, one sentence and, where there is one, the action that fills it. */
@Composable
fun EmptyState(icon: ImageVector, title: String, text: String, action: String? = null, onAction: (() -> Unit)? = null) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(56.dp))
        Text(title, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
        Text(text, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
        if (action != null && onAction != null) Button(onClick = onAction) { Text(action) }
    }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary, modifier = modifier.padding(top = 8.dp))
}

/**
 * A list that folds away under its header. The header keeps the count, so a folded list still says what it holds;
 * long lists start folded. The state survives leaving and returning to the screen within the same session.
 */
@Composable
fun CollapsibleSection(
    title: String,
    count: Int? = null,
    initiallyExpanded: Boolean = false,
    key: String = title,
    content: @Composable () -> Unit,
) {
    var open by rememberSaveable(key) { mutableStateOf(initiallyExpanded) }
    Row(
        Modifier.fillMaxWidth().clickable { open = !open }.padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(title + (count?.let { "（$it）" } ?: ""), style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
        Text(if (open) "收合" else "展開", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Icon(
            WalletIcons.Chevron, contentDescription = null, tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(20.dp).rotate(if (open) 90f else 0f),
        )
    }
    if (open) Column(verticalArrangement = Arrangement.spacedBy(10.dp)) { content() }
}

/**
 * A row that starts something: symbol, title, one line of detail and a chevron. A row that cannot be used now
 * stays visible, greyed, and its detail says why.
 */
@Composable
fun ActionRow(
    icon: ImageVector,
    title: String,
    detail: String,
    enabled: Boolean = true,
    /** Drawn in place of [icon], e.g. an issuer logo. */
    leading: (@Composable () -> Unit)? = null,
    onClick: () -> Unit,
) {
    Card(
        Modifier.fillMaxWidth().then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier),
        shape = RoundedCornerShape(Tokens.CardRadius),
        colors = CardDefaults.cardColors(
            containerColor = if (enabled) MaterialTheme.colorScheme.surfaceContainerLow else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        ),
    ) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (leading != null) leading()
            else Icon(icon, contentDescription = null, tint = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                modifier = Modifier.size(28.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium,
                    color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.outline)
                Text(detail, style = MaterialTheme.typography.bodySmall)
            }
            if (enabled) Icon(WalletIcons.Chevron, contentDescription = null, tint = MaterialTheme.colorScheme.outline, modifier = Modifier.size(20.dp))
        }
    }
}

/** A failure inside a screen, with its retry; the user never has to reopen the screen. */
@Composable
fun InlineError(text: String, onRetry: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        OutlinedButton(onClick = onRetry) { Text("重試") }
    }
}

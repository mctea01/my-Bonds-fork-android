package diw.wallet.app.desktop

import androidx.compose.ui.geometry.Rect
import java.awt.AWTEvent
import java.awt.KeyboardFocusManager
import java.awt.MouseInfo
import java.awt.Robot
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.util.concurrent.ConcurrentHashMap
import javax.swing.JFrame
import javax.swing.SwingUtilities

/**
 * DIW_EXERCISE_INPUT=1 (tools/desktop-native.sh only, with DIW_EXIT_AFTER_SECONDS and an empty DIW_WALLET_HOME): drives
 * the window with java.awt.Robot the way a person would, so the input paths go through the platform's own AWT code.
 * Under the tracing agent this records the JNI and reflection they need (AWT's native code builds every KeyEvent and
 * reads the clipboard); against the native executable it checks that typing, the context menu and pasting work.
 * Steps: type the App PIN into the first field (with a Backspace), right-click the second field and close the menu,
 * paste the PIN there from the clipboard, press the create button, wait for the main screen and right-click it.
 */
internal object InputExercise {
    val enabled = System.getenv("DIW_EXERCISE_INPUT") == "1"
    const val PIN = "135790"

    /** Where the unlock screen's targets are, in window pixels, set by the screen while [enabled]. */
    private val targets = ConcurrentHashMap<String, Rect>()
    @Volatile var window: JFrame? = null
    @Volatile var density = 1f
    @Volatile var pin = ""
    @Volatile var confirm = ""
    @Volatile var mainScreen = false

    /** Null while running (or not started); then "ok" with where the focus was, or what failed. */
    @Volatile var result: String? = null
        private set

    fun place(name: String, bounds: Rect) {
        targets[name] = bounds
    }

    fun start() {
        if (!enabled) return
        Thread({
            result = try {
                run()
                "ok (${focus()}; components=${components()}; threads=${threads()})"
            } catch (e: Throwable) {
                e.printStackTrace()
                (e.message ?: e::class.java.name) + "; " + diagnostics()
            }
            println("input exercise: $result")
        }, "input-exercise").apply { isDaemon = true; start() }
    }

    /** AWT events seen while the exercise runs, by class and id, to tell where input stops when a step fails. */
    private val seen = ConcurrentHashMap<String, Int>()

    private fun listen() {
        val mask = AWTEvent.KEY_EVENT_MASK or AWTEvent.MOUSE_EVENT_MASK or AWTEvent.INPUT_METHOD_EVENT_MASK or
            AWTEvent.FOCUS_EVENT_MASK or AWTEvent.WINDOW_FOCUS_EVENT_MASK
        Toolkit.getDefaultToolkit().addAWTEventListener({ e -> seen.merge("${e.javaClass.simpleName}:${e.id}", 1, Int::plus) }, mask)
    }

    /**
     * What AWT received, which component had the focus, and whether a key event posted straight to the event queue
     * (bypassing the platform's native key handling) reaches the field.
     */
    private fun focus(): String {
        var text = "?"
        runCatching {
            SwingUtilities.invokeAndWait {
                val kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager()
                text = "owner=${kfm.focusOwner?.javaClass?.name} window=${kfm.activeWindow?.javaClass?.name} " +
                    "im=${kfm.focusOwner?.inputContext?.javaClass?.name} pointer=${MouseInfo.getPointerInfo()?.location} " +
                    "d3d=${System.getProperty("sun.java2d.d3d")}"
            }
        }
        return text
    }

    private fun diagnostics(): String = runCatching {
        val focus = focus()
        val before = pin
        val posted = KeyboardFocusManager.getCurrentKeyboardFocusManager().focusOwner?.let { postKeys(it, before) } ?: "no focus owner"
        "events=${seen.toSortedMap()} $focus posted keys $posted; ${canvasFocus()}; components=${components()}; " +
            "os=${System.getProperty("os.version")}; threads=${threads()}"
    }.getOrElse { "diagnostics failed: $it" }

    /** Posts a typed '7' to [target] through the event queue, bypassing the platform's key handling. */
    private fun postKeys(target: java.awt.Component, before: String): String {
        val queue = Toolkit.getDefaultToolkit().systemEventQueue
        val now = System.currentTimeMillis()
        queue.postEvent(KeyEvent(target, KeyEvent.KEY_PRESSED, now, 0, KeyEvent.VK_7, '7'))
        queue.postEvent(KeyEvent(target, KeyEvent.KEY_TYPED, now, 0, KeyEvent.VK_UNDEFINED, '7'))
        queue.postEvent(KeyEvent(target, KeyEvent.KEY_RELEASED, now, 0, KeyEvent.VK_7, '7'))
        Thread.sleep(1500)
        return if (pin != before) "reached the field" else "did not reach the field"
    }

    /** Whether the Skia canvas takes the focus when asked, and whether keys posted to it reach the field then. */
    private fun canvasFocus(): String {
        var canvas: java.awt.Component? = null
        SwingUtilities.invokeAndWait { canvas = window?.let { all(it) }?.firstOrNull { it.javaClass.name.startsWith("org.jetbrains.skiko.SkiaLayer$") } }
        val c = canvas ?: return "no skia canvas"
        var asked = false
        SwingUtilities.invokeAndWait { asked = c.requestFocusInWindow() }
        Thread.sleep(1000)
        val owner = KeyboardFocusManager.getCurrentKeyboardFocusManager().focusOwner?.javaClass?.name
        return "canvas ${c.javaClass.name} asked=$asked owner=$owner keys ${postKeys(c, pin)}"
    }

    private fun all(root: java.awt.Component): List<java.awt.Component> =
        listOf(root) + ((root as? java.awt.Container)?.components?.flatMap { all(it) } ?: emptyList())

    /** The window's components: class, heavyweight or not, focusable, showing, size. */
    private fun components(): String {
        var text = "?"
        SwingUtilities.invokeAndWait {
            text = window?.let { w ->
                all(w).joinToString(" ") { c ->
                    "${c.javaClass.name.substringAfterLast('.')}[${if (c.isLightweight) "lw" else "hw"}" +
                        "${if (c.isFocusable) ",f" else ""}${if (c.isShowing) ",s" else ""},${c.width}x${c.height}]"
                }
            } ?: "no window"
        }
        return text
    }

    /** State and top frames of the AWT, Swing and Skiko threads, to see whether the toolkit thread still pumps. */
    private fun threads(): String = Thread.getAllStackTraces().entries
        .filter { (t, _) -> t.name.startsWith("AWT") || t.name.contains("skiko", true) || t.name.contains("Toolkit") }
        .joinToString(" | ") { (t, stack) -> "${t.name} ${t.state}: " + stack.take(6).joinToString(" < ") }

    private fun run() {
        listen()
        waitFor("the unlock screen", 60) { window != null && targets.containsKey("pin") && targets.containsKey("unlock") }
        val firstRun = targets.containsKey("confirm")
        val frame = window!!
        SwingUtilities.invokeAndWait { frame.toFront(); frame.requestFocus() }
        val robot = Robot().apply { autoDelay = 30 }
        robot.waitForIdle()

        click(robot, "pin")
        type(robot, PIN + "1")
        key(robot, KeyEvent.VK_BACK_SPACE)
        waitFor("typed PIN (got \"$pin\")", 10) { pin == PIN }

        val second = if (firstRun) "confirm" else "pin"
        click(robot, second)
        click(robot, second, InputEvent.BUTTON3_DOWN_MASK)
        Thread.sleep(800)
        key(robot, KeyEvent.VK_ESCAPE)
        Thread.sleep(300)
        SwingUtilities.invokeAndWait { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(PIN), null) }
        click(robot, second)
        if (!firstRun) chord(robot, KeyEvent.VK_A)
        chord(robot, KeyEvent.VK_V)
        if (firstRun) waitFor("pasted PIN (got \"$confirm\")", 10) { confirm == PIN } else waitFor("pasted PIN (got \"$pin\")", 10) { pin == PIN }
        var pasted: Any? = null
        SwingUtilities.invokeAndWait { pasted = Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) }
        check(pasted == PIN) { "clipboard holds \"$pasted\"" }

        click(robot, "unlock")
        waitFor("the main screen", 120) { mainScreen }
        Thread.sleep(1500)
        val r = frame.contentPane.let { c -> java.awt.Rectangle(c.locationOnScreen, c.size) }
        robot.mouseMove(r.x + r.width / 2, r.y + r.height / 2)
        robot.mousePress(InputEvent.BUTTON3_DOWN_MASK)
        robot.mouseRelease(InputEvent.BUTTON3_DOWN_MASK)
        Thread.sleep(800)
        key(robot, KeyEvent.VK_ESCAPE)
        robot.waitForIdle()
    }

    private fun waitFor(what: String, seconds: Int, done: () -> Boolean) {
        val end = System.nanoTime() + seconds * 1_000_000_000L
        while (!done()) {
            if (System.nanoTime() > end) throw IllegalStateException("timed out waiting for $what")
            Thread.sleep(100)
        }
    }

    /** Clicks the middle of a target; Compose lays out in pixels, AWT places in points. */
    private fun click(robot: Robot, name: String, button: Int = InputEvent.BUTTON1_DOWN_MASK) {
        val b = targets.getValue(name)
        var origin = java.awt.Point()
        SwingUtilities.invokeAndWait { origin = window!!.contentPane.locationOnScreen }
        robot.mouseMove(origin.x + (b.center.x / density).toInt(), origin.y + (b.center.y / density).toInt())
        robot.mousePress(button)
        robot.mouseRelease(button)
        robot.waitForIdle()
        Thread.sleep(200)
    }

    private fun key(robot: Robot, code: Int) {
        robot.keyPress(code)
        robot.keyRelease(code)
        robot.waitForIdle()
    }

    private fun type(robot: Robot, text: String) {
        for (c in text) key(robot, KeyEvent.getExtendedKeyCodeForChar(c.code))
    }

    private fun chord(robot: Robot, code: Int) {
        robot.keyPress(KeyEvent.VK_CONTROL)
        key(robot, code)
        robot.keyRelease(KeyEvent.VK_CONTROL)
        robot.waitForIdle()
        Thread.sleep(200)
    }
}

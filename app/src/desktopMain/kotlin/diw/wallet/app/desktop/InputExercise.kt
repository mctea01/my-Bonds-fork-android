package diw.wallet.app.desktop

import androidx.compose.ui.geometry.Rect
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

    /** Null while running (or not started); then "ok" or what failed. */
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
                "ok"
            } catch (e: Throwable) {
                e.printStackTrace()
                e.message ?: e::class.java.name
            }
            println("input exercise: $result")
        }, "input-exercise").apply { isDaemon = true; start() }
    }

    private fun run() {
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

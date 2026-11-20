package diw.wallet.app.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

/**
 * Input exercise diagnostics on Windows only: which window the OS finds at a screen point and which window is in the
 * foreground, by class, process and whether Windows considers it hung. AWT's own check only says "not this window";
 * this tells a window of another process, a ghost window (DWM replaces a window that stopped reading its messages)
 * and a child window that is not AWT's apart.
 */
internal object WindowProbe {
    @Suppress("FunctionName")
    private interface User32 : Library {
        /** POINT by value: on x64 the two ints travel as one 64-bit argument, x in the low half. */
        fun WindowFromPoint(point: Long): Pointer?
        fun GetForegroundWindow(): Pointer?
        fun GetAncestor(hwnd: Pointer, flags: Int): Pointer?
        fun GetClassNameW(hwnd: Pointer, name: CharArray, max: Int): Int
        fun GetWindowThreadProcessId(hwnd: Pointer, pid: IntArray): Int
        fun IsHungAppWindow(hwnd: Pointer): Boolean
    }

    private interface Kernel32 : Library {
        fun GetCurrentProcessId(): Int
    }

    private val windows = System.getProperty("os.name").orEmpty().startsWith("Windows")
    private val user32 by lazy { Native.load("user32", User32::class.java) }
    private val kernel32 by lazy { Native.load("kernel32", Kernel32::class.java) }

    fun at(x: Int, y: Int): String {
        if (!windows) return ""
        return try {
            val point = (y.toLong() shl 32) or (x.toLong() and 0xffffffffL)
            "osWindow=${describe(user32.WindowFromPoint(point))} foreground=${describe(user32.GetForegroundWindow())}"
        } catch (e: Throwable) {
            "osWindow=unavailable (${e::class.java.simpleName}: ${e.message})"
        }
    }

    private fun describe(hwnd: Pointer?): String {
        if (hwnd == null) return "none"
        val root = user32.GetAncestor(hwnd, GA_ROOT) ?: hwnd
        val self = kernel32.GetCurrentProcessId()
        return one(hwnd, self) + if (Pointer.nativeValue(root) != Pointer.nativeValue(hwnd)) " root ${one(root, self)}" else ""
    }

    private fun one(hwnd: Pointer, self: Int): String {
        val name = CharArray(256)
        val length = user32.GetClassNameW(hwnd, name, name.size)
        val pid = IntArray(1)
        user32.GetWindowThreadProcessId(hwnd, pid)
        val owner = if (pid[0] == self) "this process" else "pid ${pid[0]}"
        val hung = if (user32.IsHungAppWindow(hwnd)) " hung" else ""
        return "[${String(name, 0, length.coerceAtLeast(0))} $owner$hung]"
    }

    private const val GA_ROOT = 2
}

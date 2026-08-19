package com.droidseal.antidebug

import android.os.Debug
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicLong

/**
 * DroidSeal opt-in anti-debug stub — self-developed, MIT.
 *
 * Detection ONLY. This object never crashes, exits, or changes app behaviour on
 * its own. Call [inspect] to read signals, then decide the response in your app
 * (prefer treating these as risk inputs feeding a server-side decision, not as
 * the sole access control). Build-time linked; it is not injected into a
 * finished APK after the fact.
 */
object DroidSealAntiDebug {
    /** Process-wide minimum interval for resumed-Activity rechecks. */
    const val DEFAULT_RESUME_RECHECK_INTERVAL_MS: Long = 2_000L

    private val lastResumeInspectionMs = AtomicLong(-1L)

    @Volatile
    private var nativeAvailable: Boolean = false

    init {
        nativeAvailable = try {
            System.loadLibrary("droidseal_antidebug")
            true
        } catch (t: Throwable) {
            false
        }
    }

    /** Point-in-time snapshot of the available anti-debug signals. */
    data class Report(
        val nativeAvailable: Boolean,
        val tracerPid: Int,
        val injectionArtifacts: Boolean,
        val javaDebuggerConnected: Boolean,
        val waitingForDebugger: Boolean,
    ) {
        /** True if any signal indicates a debugger or instrumentation framework. */
        val suspicious: Boolean
            get() = tracerPid > 0 ||
                injectionArtifacts ||
                javaDebuggerConnected ||
                waitingForDebugger
    }

    /** Collect all signals. Native failures degrade to safe defaults. */
    fun inspect(): Report {
        val tracer = if (nativeAvailable) safeTracerPid() else -1
        val artifacts = if (nativeAvailable) safeArtifacts() else false
        return Report(
            nativeAvailable = nativeAvailable,
            tracerPid = tracer,
            injectionArtifacts = artifacts,
            javaDebuggerConnected = Debug.isDebuggerConnected(),
            waitingForDebugger = Debug.waitingForDebugger(),
        )
    }

    /**
     * Convenience: run [inspect] and invoke [onDetected] only when a signal
     * fires. The callback owns the response (log, degrade, report to server...).
     */
    fun guard(onDetected: (Report) -> Unit) {
        val report = inspect()
        if (report.suspicious) {
            onDetected(report)
        }
    }

    /**
     * Recheck when a host Activity reaches onResume. Calls across all Activities
     * share a monotonic, process-wide throttle so rapid navigation does not scan
     * /proc/maps repeatedly. Returns null when throttled; otherwise returns the
     * report and invokes [onDetected] only for suspicious signals.
     *
     * This method only detects. It never exits, kills, or changes app behaviour.
     */
    fun guardOnActivityResumed(
        minIntervalMs: Long = DEFAULT_RESUME_RECHECK_INTERVAL_MS,
        onDetected: (Report) -> Unit,
    ): Report? {
        val interval = minIntervalMs.coerceAtLeast(0L)
        while (true) {
            val now = SystemClock.elapsedRealtime()
            val previous = lastResumeInspectionMs.get()
            if (previous >= 0L && now - previous < interval) {
                return null
            }
            if (lastResumeInspectionMs.compareAndSet(previous, now)) {
                val report = inspect()
                if (report.suspicious) {
                    onDetected(report)
                }
                return report
            }
        }
    }

    private fun safeTracerPid(): Int = try {
        nativeTracerPid()
    } catch (t: Throwable) {
        -1
    }

    private fun safeArtifacts(): Boolean = try {
        nativeHasInjectionArtifacts()
    } catch (t: Throwable) {
        false
    }

    private external fun nativeTracerPid(): Int

    private external fun nativeHasInjectionArtifacts(): Boolean
}

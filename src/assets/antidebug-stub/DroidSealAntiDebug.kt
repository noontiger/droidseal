package com.droidseal.antidebug

import android.os.Debug
import android.os.SystemClock
import android.util.Log
import java.util.concurrent.atomic.AtomicLong
import kotlin.system.exitProcess

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

    private const val TAG = "DroidSealAntiDebug"

    /** 处置策略：检测到异常信号后的动作（默认 LOG_ONLY，与旧行为一致）。 */
    enum class ResponsePolicy { LOG_ONLY, WARN, EXIT }

    /** 处置选项：由应用决定启用哪个策略；stub 默认不执行任何阻断动作。 */
    data class GuardOptions(
        val policy: ResponsePolicy = ResponsePolicy.LOG_ONLY,
        val exitDelayMs: Long = 0L,
        val exitAction: (() -> Unit)? = null,
        val onDetected: ((Report) -> Unit)? = null,
    )

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
     * 带处置策略的守卫。默认 LOG_ONLY（仅回调/记录，不阻断）；显式启用
     * [ResponsePolicy.WARN] 输出警告日志，[ResponsePolicy.EXIT] 会在延迟后
     * 调用 exitAction（默认 exitProcess）真正阻止应用继续运行。
     */
    fun guard(options: GuardOptions = GuardOptions()) {
        val report = inspect()
        if (report.suspicious) {
            applyPolicy(report, options)
        }
    }

    private fun applyPolicy(report: Report, options: GuardOptions) {
        options.onDetected?.invoke(report)
        when (options.policy) {
            ResponsePolicy.LOG_ONLY -> Unit
            ResponsePolicy.WARN -> Log.w(TAG, "检测到可疑运行环境：$report")
            ResponsePolicy.EXIT -> {
                Log.w(TAG, "检测到可疑运行环境，${options.exitDelayMs}ms 后退出：$report")
                Thread {
                    Thread.sleep(options.exitDelayMs.coerceAtLeast(0L))
                    (options.exitAction ?: { exitProcess(1) }).invoke()
                }.start()
            }
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

    /** 带处置策略的 resumed 守卫：EXIT 策略下检测到异常会按 exitAction 阻断。 */
    fun guardOnActivityResumed(
        options: GuardOptions,
        minIntervalMs: Long = DEFAULT_RESUME_RECHECK_INTERVAL_MS,
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
                    applyPolicy(report, options)
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

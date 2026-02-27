package org.matrix.TEESimulator.util

import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader
import org.matrix.TEESimulator.logging.SystemLogger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

object ShellUtils {

    data class CommandResult(
        val exitCode: Int,
        val stdout: List<String>,
        val stderr: List<String>
    ) {
        fun isSuccess() = exitCode == 0
    }

    /**
     * Executes a command using 'su' (root shell).
     * If 'su' is not available, it falls back to 'sh' but might fail due to permissions.
     */
    fun execRoot(command: String): CommandResult {
        return exec(command, useRoot = true)
    }

    /**
     * Executes a command using 'sh' (normal shell).
     */
    fun exec(command: String, useRoot: Boolean = false): CommandResult {
        val shell = if (useRoot) "su" else "sh"
        val process = Runtime.getRuntime().exec(shell)
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()

        try {
            DataOutputStream(process.outputStream).use { os ->
                os.writeBytes(command + "\n")
                os.writeBytes("exit\n")
                os.flush()
            }

            // Use CountDownLatch to wait for both stream readers to complete
            val latch = CountDownLatch(2)

            thread {
                try {
                    BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            synchronized(stdout) {
                                stdout.add(line!!)
                            }
                        }
                    }
                } catch (e: Exception) {
                    synchronized(stderr) {
                        stderr.add("Error reading stdout: ${e.message}")
                    }
                } finally {
                    latch.countDown()
                }
            }

            thread {
                try {
                    BufferedReader(InputStreamReader(process.errorStream)).use { reader ->
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            synchronized(stderr) {
                                stderr.add(line!!)
                            }
                        }
                    }
                } catch (e: Exception) {
                    synchronized(stderr) {
                        stderr.add("Error reading stderr: ${e.message}")
                    }
                } finally {
                    latch.countDown()
                }
            }

            // Wait for process to exit
            val exitCode = process.waitFor()
            
            // Wait for stream readers to finish (with timeout to prevent hanging)
            if (!latch.await(5, TimeUnit.SECONDS)) {
                SystemLogger.warning("Timed out waiting for shell output streams")
            }
            
            return CommandResult(exitCode, stdout, stderr)

        } catch (e: Exception) {
            val errorMsg = "Exception executing command '$command': ${e.message}"
            SystemLogger.error(errorMsg, e)
            stderr.add(errorMsg)
            return CommandResult(-1, stdout, stderr)
        }
    }

    /**
     * Checks if a file exists using shell commands (useful for root-only paths).
     */
    fun fileExists(path: String): Boolean {
        val result = execRoot("[ -e \"$path\" ]")
        return result.isSuccess()
    }

    /**
     * Reads file content using cat (useful for root-only paths).
     */
    fun readFile(path: String): List<String> {
        val result = execRoot("cat \"$path\"")
        return if (result.isSuccess()) result.stdout else emptyList()
    }

    /**
     * Escapes a string for use as a single argument in a shell command.
     * Wraps the string in single quotes and escapes any internal single quotes.
     * Example: foo'bar -> 'foo'\''bar'
     */
    fun escapeShellArg(arg: String): String {
        return "'" + arg.replace("'", "'\\''") + "'"
    }
}

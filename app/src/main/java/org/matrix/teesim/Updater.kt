package org.matrix.teesim

import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject

/**
 * Canary self-update. CI publishes rolling `canary-<code>` GitHub prereleases (keeping the
 * newest five) with the Release/Debug module zips as assets. The daemon — which has root and
 * network — checks GitHub, and on request downloads a build and hands it to the root manager
 * to flash, so the WebUI needs neither a GitHub account nor external network access.
 */
object Updater {

    private const val REPO = "JingMatrix/TEESimulator"
    private const val API = "https://api.github.com/repos/$REPO/releases?per_page=30"

    /** The installed module's versionCode (git commit count), read from its module.prop. */
    private fun currentCode(): Int {
        for (p in
            listOf(
                "/data/adb/modules/teesim/module.prop",
                "/data/adb/modules_update/teesim/module.prop",
            )) {
            val f = File(p)
            if (!f.isFile) continue
            f.readLines().forEach {
                if (it.startsWith("versionCode="))
                    return it.substringAfter("=").trim().toIntOrNull() ?: 0
            }
        }
        return 0
    }

    /** The installed module's version name, e.g. "v4.0 (17-abc1234-debug)", from its module.prop. */
    private fun currentVersion(): String {
        for (p in
            listOf(
                "/data/adb/modules/teesim/module.prop",
                "/data/adb/modules_update/teesim/module.prop",
            )) {
            val f = File(p)
            if (!f.isFile) continue
            f.readLines().forEach {
                if (it.startsWith("version=")) return it.substringAfter("=").trim()
            }
        }
        return ""
    }

    private fun httpGet(url: String): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 15000
        c.readTimeout = 20000
        c.instanceFollowRedirects = true
        c.setRequestProperty("Accept", "application/vnd.github+json")
        c.setRequestProperty("User-Agent", "TEESimulator")
        c.inputStream.use {
            return it.readBytes().toString(Charsets.UTF_8)
        }
    }

    private fun newestCanary(releases: JSONArray): Pair<Int, JSONObject>? {
        var best: JSONObject? = null
        var bestCode = -1
        for (i in 0 until releases.length()) {
            val r = releases.getJSONObject(i)
            val tag = r.optString("tag_name")
            if (!tag.startsWith("canary-")) continue
            val code = tag.substringAfter("canary-").toIntOrNull() ?: continue
            if (code > bestCode) {
                bestCode = code
                best = r
            }
        }
        return best?.let { bestCode to it }
    }

    /**
     * { ok, currentCode, installedVersion, latest:{ code, tag, name, notes, htmlUrl, commit,
     * assets[] }|null, updateAvailable }.
     */
    fun status(): JSONObject {
        return try {
            val cur = currentCode()
            val newest = newestCanary(JSONArray(httpGet(API)))
            val latest =
                newest?.let { (code, r) ->
                    val assets = JSONArray()
                    val ja = r.optJSONArray("assets") ?: JSONArray()
                    for (i in 0 until ja.length()) {
                        val a = ja.getJSONObject(i)
                        assets.put(
                            JSONObject().put("name", a.optString("name")).put("size", a.optLong("size"))
                        )
                    }
                    JSONObject()
                        .put("code", code)
                        .put("tag", r.optString("tag_name"))
                        .put("name", r.optString("name"))
                        .put("notes", r.optString("body"))
                        .put("htmlUrl", r.optString("html_url"))
                        .put("commit", r.optString("target_commitish"))
                        .put("assets", assets)
                }
            JSONObject()
                .put("ok", true)
                .put("currentCode", cur)
                .put("installedVersion", currentVersion())
                .put("latest", latest ?: JSONObject.NULL)
                .put("updateAvailable", (newest?.first ?: -1) > cur)
        } catch (e: Exception) {
            SystemLogger.warning("Updater: status check failed", e)
            JSONObject().put("ok", false).put("error", e.message ?: "network error")
        }
    }

    /** Download the tag's <variant> zip and flash it via the detected root manager. */
    fun install(tag: String, variant: String): JSONObject {
        return try {
            if (!tag.matches(Regex("^canary-\\d+$"))) return fail("bad tag")
            val v = if (variant.equals("debug", true)) "Debug" else "Release"
            val releases = JSONArray(httpGet(API))
            var url: String? = null
            for (i in 0 until releases.length()) {
                val r = releases.getJSONObject(i)
                if (r.optString("tag_name") != tag) continue
                val ja = r.optJSONArray("assets") ?: JSONArray()
                for (j in 0 until ja.length()) {
                    val a = ja.getJSONObject(j)
                    if (a.optString("name").endsWith("-$v.zip")) {
                        url = a.optString("browser_download_url")
                        break
                    }
                }
            }
            url ?: return fail("no $v asset for $tag")
            val zip = File(Const.DATA_DIR, ".canary.zip")
            download(url, zip)
            val res = flash(zip)
            zip.delete()
            res
        } catch (e: Exception) {
            SystemLogger.error("Updater: install failed", e)
            fail(e.message ?: "install error")
        }
    }

    private fun download(url: String, dest: File) {
        val c = URL(url).openConnection() as HttpURLConnection
        c.instanceFollowRedirects = true
        c.setRequestProperty("User-Agent", "TEESimulator")
        c.connectTimeout = 15000
        c.readTimeout = 120000
        c.inputStream.use { input -> dest.outputStream().use { input.copyTo(it) } }
    }

    /** Try each known root manager's module-install CLI until one succeeds. */
    private fun flash(zip: File): JSONObject {
        val managers =
            listOf(
                listOf("ksud", "module", "install", zip.absolutePath),
                listOf("magisk", "--install-module", zip.absolutePath),
                listOf("/data/adb/ap/bin/apd", "module", "install", zip.absolutePath),
                listOf("/data/adb/apd", "module", "install", zip.absolutePath),
            )
        var last = ""
        for (cmd in managers) {
            try {
                val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
                val out = p.inputStream.bufferedReader().readText()
                if (p.waitFor(120, TimeUnit.SECONDS) && p.exitValue() == 0) {
                    SystemLogger.info("Updater: flashed via ${cmd[0]}")
                    return JSONObject().put("ok", true).put("message", "Installed — reboot to apply.")
                }
                last = "${cmd[0]}: ${out.trim()}"
            } catch (e: Exception) {
                last = "${cmd[0]}: ${e.message}"
            }
        }
        return fail("no root manager could install the zip ($last)")
    }

    private fun fail(msg: String) = JSONObject().put("ok", false).put("error", msg)
}

package com.th3next.security

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.documentfile.provider.DocumentFile
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val pickFolderCode = 4102
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var status: TextView
    private lateinit var results: TextView
    private lateinit var scanButton: Button
    private var selectedTree: Uri? = null
    private val quarantineDir by lazy { File(filesDir, "quarantine").apply { mkdirs() } }
    private val findings = mutableListOf<Finding>()

    data class Finding(val uri: Uri, val name: String, val reason: String, val sha256: String)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
    }

    private fun buildUi() {
        val navy = 0xFF101D2D.toInt()
        val cyan = 0xFF12B8D6.toInt()
        val white = 0xFFFFFFFF.toInt()
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 34, 28, 24)
            setBackgroundColor(navy)
        }
        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, 24)
        }
        val title = TextView(this).apply {
            text = "TH3N3XT SECURITY"
            textSize = 25f
            setTextColor(white)
            gravity = Gravity.CENTER
        }
        val subtitle = TextView(this).apply {
            text = "ANDROID FILE SECURITY SCANNER"
            textSize = 12f
            setTextColor(0xFF9CB3C8.toInt())
            gravity = Gravity.CENTER
            setPadding(0, 8, 0, 24)
        }
        status = TextView(this).apply {
            text = "Status: siap. Pilih folder yang ingin diperiksa."
            textSize = 15f
            setTextColor(white)
            setPadding(0, 18, 0, 18)
        }
        results = TextView(this).apply {
            text = "Belum ada hasil pemindaian."
            textSize = 14f
            setTextColor(0xFFD6E2EE.toInt())
            setPadding(0, 16, 0, 16)
        }
        val chooseButton = makeButton("1. PILIH FOLDER", cyan, navy)
        scanButton = makeButton("2. MULAI FULL SCAN", 0xFF238B68.toInt(), white).apply { isEnabled = false }
        val quarantineButton = makeButton("KARANTINA TEMUAN TERPILIH", 0xFFB7791F.toInt(), white)
        val viewQuarantineButton = makeButton("LIHAT KARANTINA", 0xFF34495E.toInt(), white)
        val deleteButton = makeButton("HAPUS PERMANEN DARI KARANTINA", 0xFF9B3434.toInt(), white)

        chooseButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
            startActivityForResult(intent, pickFolderCode)
        }
        scanButton.setOnClickListener { startScan() }
        quarantineButton.setOnClickListener { showQuarantineChoice() }
        viewQuarantineButton.setOnClickListener { showQuarantineContents() }
        deleteButton.setOnClickListener { confirmDeleteQuarantine() }

        content.addView(title)
        content.addView(subtitle)
        content.addView(status)
        content.addView(chooseButton)
        content.addView(scanButton)
        content.addView(results)
        content.addView(quarantineButton)
        content.addView(viewQuarantineButton)
        content.addView(deleteButton)
        val note = TextView(this).apply {
            text = "\nCATATAN KEMAMPUAN\nAplikasi ini memindai file dalam folder yang kamu pilih. Versi awal mengenali signature uji EICAR dan memberi tanda pada APK untuk pemeriksaan manual. Ini bukan mesin antivirus penuh dan tidak dapat memindai area privat aplikasi lain atau menghapus malware sistem tanpa hak khusus."
            textSize = 12f
            setTextColor(0xFF9CB3C8.toInt())
            setPadding(0, 18, 0, 0)
        }
        content.addView(note)
        scroll.addView(content)
        page.addView(scroll)
        setContentView(page)
    }

    private fun makeButton(label: String, bg: Int, fg: Int): Button =
        Button(this).apply {
            text = label
            textSize = 13f
            setTextColor(fg)
            setBackgroundColor(bg)
            isAllCaps = false
            val lp = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            lp.setMargins(0, 7, 0, 7)
            layoutParams = lp
        }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == pickFolderCode && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            val flags = data.flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            contentResolver.takePersistableUriPermission(uri, flags)
            selectedTree = uri
            scanButton.isEnabled = true
            status.text = "Folder dipilih. Siap memindai."
            results.text = uri.lastPathSegment ?: uri.toString()
        }
    }

    private fun startScan() {
        val tree = selectedTree ?: return
        scanButton.isEnabled = false
        status.text = "Sedang memindai…"
        results.text = "Memeriksa file yang dapat diakses."
        executor.execute {
            val found = mutableListOf<Finding>()
            var checked = 0
            try {
                val rootDoc = DocumentFile.fromTreeUri(this, tree)
                if (rootDoc != null) scanDocumentTree(rootDoc, found) { checked++ }
            } catch (e: Exception) {
                runOnUiThread {
                    status.text = "Pemindaian terhenti: ${e.localizedMessage ?: "kesalahan akses"}"
                    scanButton.isEnabled = true
                }
                return@execute
            }
            synchronized(findings) {
                findings.clear()
                findings.addAll(found)
            }
            runOnUiThread {
                scanButton.isEnabled = true
                status.text = "Pemindaian selesai. File diperiksa: $checked"
                results.text = if (found.isEmpty()) {
                    "Tidak ditemukan signature ancaman uji yang dikenal.\nIni bukan jaminan perangkat bebas malware."
                } else {
                    found.mapIndexed { i, f ->
                        "${i + 1}. ${f.name}\n${f.reason}\nSHA-256: ${f.sha256}"
                    }.joinToString("\n\n")
                }
            }
        }
    }

    private fun scanDocumentTree(
        doc: DocumentFile,
        found: MutableList<Finding>,
        onChecked: () -> Unit
    ) {
        if (doc.isDirectory) {
            doc.listFiles().forEach { child -> scanDocumentTree(child, found, onChecked) }
            return
        }
        if (!doc.isFile) return
        onChecked()
        val name = doc.name ?: "unknown"
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val sample = ByteArray(8192)
            val marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE".toByteArray(Charsets.US_ASCII)
            var carry = ByteArray(0)
            contentResolver.openInputStream(doc.uri)?.use { input ->
                while (true) {
                    val n = input.read(sample)
                    if (n <= 0) break
                    digest.update(sample, 0, n)
                    val combined = carry + sample.copyOfRange(0, n)
                    if (containsBytes(combined, marker)) {
                        val hash = digest.digest().joinToString("") { "%02x".format(it) }
                        found.add(Finding(doc.uri, name, "Signature uji EICAR ditemukan (file uji, bukan virus aktif).", hash))
                        return
                    }
                    carry = if (combined.size > marker.size) combined.copyOfRange(combined.size - marker.size, combined.size) else combined
                }
            }
            // APK files are reported for manual review, never automatically classified as malware.
            if (name.endsWith(".apk", ignoreCase = true)) {
                val hash = digest.digest().joinToString("") { "%02x".format(it) }
                found.add(Finding(doc.uri, name, "File APK ditemukan; perlu pemeriksaan lanjutan. Bukan vonis malware.", hash))
            }
        } catch (_: Exception) {
            // Inaccessible or provider-protected files are skipped; the report does not claim they are clean.
        }
    }

    private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    private fun showQuarantineChoice() {
        val list = synchronized(findings) { findings.toList() }
        if (list.isEmpty()) {
            AlertDialog.Builder(this).setMessage("Belum ada temuan untuk dikarantina.").setPositiveButton("OK", null).show()
            return
        }
        val labels = list.map { "${it.name} — ${it.reason}" }.toTypedArray()
        val checked = BooleanArray(list.size)
        AlertDialog.Builder(this)
            .setTitle("Pilih file untuk dikarantina")
            .setMultiChoiceItems(labels, checked) { _, which, isChecked -> checked[which] = isChecked }
            .setPositiveButton("Karantina") { _, _ ->
                val chosen = list.filterIndexed { index, _ -> checked[index] }
                quarantine(chosen)
            }
            .setNegativeButton("Batal", null)
            .show()
    }

    private fun quarantine(items: List<Finding>) {
        if (items.isEmpty()) return
        executor.execute {
            var moved = 0
            val tree = selectedTree
            items.forEach { item ->
                try {
                    val safeName = "${System.currentTimeMillis()}_${item.name.replace(Regex("[^A-Za-z0-9._-]"), "_")}"
                    val target = File(quarantineDir, safeName)
                    contentResolver.openInputStream(item.uri)?.use { input ->
                        target.outputStream().use { output -> input.copyTo(output) }
                    }
                    // Delete original only after verified copy; SAF provider may deny deletion.
                    val original = DocumentFile.fromSingleUri(this, item.uri)
                    if (target.exists() && target.length() > 0L && original?.delete() == true) moved++
                    else target.delete()
                } catch (_: Exception) { }
            }
            runOnUiThread {
                status.text = "$moved file berhasil dipindahkan ke karantina aplikasi."
                results.text = "File karantina tersimpan di penyimpanan privat aplikasi. Jika penghapusan sumber ditolak Android, file sumber tetap ada."
            }
        }
    }

    private fun showQuarantineContents() {
        val files = quarantineDir.listFiles()?.toList() ?: emptyList()
        val message = if (files.isEmpty()) "Karantina kosong." else files.joinToString("\n") { "${it.name} (${it.length()} byte)" }
        AlertDialog.Builder(this).setTitle("Karantina").setMessage(message).setPositiveButton("OK", null).show()
    }

    private fun confirmDeleteQuarantine() {
        AlertDialog.Builder(this)
            .setTitle("Hapus permanen?")
            .setMessage("Semua file di karantina aplikasi akan dihapus dan tidak dapat dipulihkan. Lanjutkan?")
            .setNegativeButton("Batal", null)
            .setPositiveButton("Hapus") { _, _ ->
                val count = quarantineDir.listFiles()?.count { it.delete() } ?: 0
                status.text = "$count file karantina dihapus."
            }.show()
    }

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }
}

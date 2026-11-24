# TH3N3XT SECURITY — Android starter project

## Isi versi 1.0
- APK Android native, minimum Android 7.0 (API 24).
- Folder dipilih sendiri melalui Android Storage Access Framework.
- Pemindaian rekursif file yang diizinkan oleh pengguna.
- SHA-256 untuk file yang diperiksa.
- Pengenalan string signature uji EICAR (file uji antivirus, bukan malware aktif).
- APK ditandai untuk pemeriksaan manual, bukan otomatis dinyatakan virus.
- Karantina ke penyimpanan privat aplikasi dan opsi hapus permanen karantina.

## Batasan penting
Ini adalah prototipe pemindai file berbasis signature, BUKAN antivirus komersial dengan cakupan penuh. Android non-root membatasi akses ke data privat aplikasi lain, partisi sistem, dan beberapa direktori. Aplikasi tidak dapat menjamin deteksi semua malware atau menghapus malware sistem. File yang tidak dapat dibaca akan dilewati dan tidak boleh dianggap bersih.

## Build
1. Buka folder proyek ini di Android Studio.
2. Gunakan JDK 17 dan Android SDK Platform 35.
3. Tunggu Gradle Sync.
4. Pilih Build > Build Bundle(s) / APK(s) > Build APK(s).
5. APK debug tersedia di `app/build/outputs/apk/debug/app-debug.apk`.

Tidak ada Gradle Wrapper yang disertakan. Android Studio dapat menggunakan Gradle yang sesuai atau membuat wrapper dari menu Gradle.

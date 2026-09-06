package org.shadow6.android.security

import android.os.Process
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

/** Atomically publish an app-private storage file with verified 0600 ownership. */
fun writePrivateConfig(directory: File, name: String, bytes: ByteArray): File {
    require(name in setOf("core-config.json", "gate-config.json") && bytes.size in 1..1_048_576)
    val root = directory.canonicalFile
    val target = File(root, name).toPath()
    require(!Files.isSymbolicLink(target)) { "Configuration must not be a symbolic link" }
    if (Files.exists(target)) require(Files.isRegularFile(target)) { "Configuration must be regular" }
    val temporary = Files.createTempFile(root.toPath(), ".shadow6-config-", ".json",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    try {
        val descriptor = Os.open(temporary.toString(), OsConstants.O_WRONLY or OsConstants.O_NOFOLLOW, 0)
        FileOutputStream(descriptor).use { stream ->
            val opened = Os.fstat(descriptor)
            val named = Os.lstat(temporary.toString())
            require(OsConstants.S_ISREG(opened.st_mode) && opened.st_uid == Process.myUid()
                && opened.st_mode and 4095 == 384 && opened.st_ino == named.st_ino && opened.st_dev == named.st_dev) {
                "Unsafe configuration ownership or permissions"
            }
            stream.write(bytes)
            stream.fd.sync()
            val written = Os.fstat(descriptor)
            require(written.st_size == bytes.size.toLong() && written.st_uid == opened.st_uid
                && written.st_mode == opened.st_mode) { "Configuration changed while writing" }
        }
        Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        val published = Os.lstat(target.toString())
        require(OsConstants.S_ISREG(published.st_mode) && published.st_uid == Process.myUid()
            && published.st_mode and 4095 == 384 && published.st_size == bytes.size.toLong())
        return target.toFile()
    } finally {
        Files.deleteIfExists(temporary)
    }
}

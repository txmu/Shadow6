package org.shadow6.android.core
import org.shadow6.android.gate.GateController

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder

class CoreService : Service() {
    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel("shadow6-core", "Shadow6 Core", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        val notification = android.app.Notification.Builder(this, "shadow6-core").setContentTitle("Shadow6").setContentText("Core service active").setSmallIcon(android.R.drawable.stat_sys_download_done).build()
        startForeground(6, notification)
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            CoreController.runtime(this).stop()
            stopSelf()
        }
        return START_STICKY
    }
    override fun onDestroy() {
        CoreController.runtime(this).stop()
        GateController.runtime(this).stop()
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val ACTION_KEEP_ALIVE = "org.shadow6.android.core.KEEP_ALIVE"
        const val ACTION_STOP = "org.shadow6.android.core.STOP"
    }
}

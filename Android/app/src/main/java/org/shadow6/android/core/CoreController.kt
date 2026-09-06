package org.shadow6.android.core

import android.content.Context

object CoreController {
    @Volatile private var runtime: CoreRuntime? = null

    fun runtime(context: Context): CoreRuntime = runtime ?: synchronized(this) {
        runtime ?: CoreRuntime(context.applicationContext).also { runtime = it }
    }
}

"""Bounded deadline/cancellation waits for existing SDK operations.

Read-only authority queries may finish after cancellation. A late attachment
is always closed. No mutation is retried and no worker pool queue is unbounded.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from threading import BoundedSemaphore, Event
import time
from .boundary import ConnectionError

_POOL=ThreadPoolExecutor(max_workers=16,thread_name_prefix='shadow6-application-open')
_SLOTS=BoundedSemaphore(16)


def bounded(operation,*,deadline,cancellation=None,attachment=False):
    if cancellation is not None and cancellation.is_set():raise ConnectionError('ConnectionCancelled',state='cancelled')
    if time.monotonic()>=deadline:raise ConnectionError('ConnectionTimedOut',retryable=True)
    if not _SLOTS.acquire(blocking=False):raise ConnectionError('ApplicationControlCapacity',retryable=True)
    abandoned=Event();claimed=Event()
    try:future=_POOL.submit(operation)
    except BaseException:_SLOTS.release();raise
    def completed(done):
        try:
            if attachment and abandoned.is_set() and not claimed.is_set():
                try:done.result().close()
                except (OSError,ValueError,RuntimeError):pass
        finally:_SLOTS.release()
    future.add_done_callback(completed)
    try:
        while True:
            if cancellation is not None and cancellation.is_set():raise ConnectionError('ConnectionCancelled',state='cancelled')
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ConnectionError('ConnectionTimedOut',retryable=True)
            try:
                value=future.result(timeout=min(.02,remaining))
                claimed.set()
                return value
            except FutureTimeout:
                if future.done():raise
    except BaseException:
        abandoned.set()
        # A completion concurrent with abandonment may have run its callback
        # just before the flag was set. Closing is idempotent.
        if attachment and future.done() and not claimed.is_set():
            try:future.result().close()
            except (OSError,ValueError,RuntimeError):pass
        raise

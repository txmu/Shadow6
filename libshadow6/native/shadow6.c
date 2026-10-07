#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "shadow6.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

struct s6_connection { PyObject *facade; PyObject *handle; int fd; int native_fd; char *descriptor; };
extern int s6_fd_open(const char *, int *, char **, char *, size_t);
static pthread_once_t runtime_once = PTHREAD_ONCE_INIT;
static void initialize(void) {
    if (!Py_IsInitialized()) { Py_Initialize(); PyEval_SaveThread(); }
}
static void error_code(s6_error *error, const char *code) {
    if (!error) return;
    error->abi_version = S6_APPLICATION_ABI_V1;
    snprintf(error->code, sizeof(error->code), "%s", code);
}
static void python_error(s6_error *error) {
    PyObject *type = NULL, *value = NULL, *trace = NULL;
    PyErr_Fetch(&type, &value, &trace);
    PyErr_NormalizeException(&type, &value, &trace);
    PyObject *code = value ? PyObject_GetAttrString(value, "code") : NULL;
    const char *text = code && PyUnicode_Check(code) ? PyUnicode_AsUTF8(code) : NULL;
    /* Structured SDK codes only; exception text may include paths/secrets. */
    int safe = text && strlen(text) < S6_ERROR_CODE_SIZE;
    if (safe) for (const char *p=text; *p; p++)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z'))) safe=0;
    error_code(error, safe ? text : "ConnectionRejected");
    Py_XDECREF(code); Py_XDECREF(type); Py_XDECREF(value); Py_XDECREF(trace);
    PyErr_Clear();
}
uint32_t s6_application_abi(void) { return S6_APPLICATION_ABI_V1; }
int s6_connection_open(uint32_t abi, const char *service, s6_connection **out, s6_error *error) {
    if (out) *out = NULL;
    if (abi != S6_APPLICATION_ABI_V1 || !out || !service || strnlen(service,4097) > 4096 || !*service) {
        error_code(error,"InvalidApplicationABIOrService"); return -1;
    }
    if (getenv("SHADOW6_CONTROL_SOCKET")) {
        s6_connection *direct=calloc(1,sizeof(*direct));
        if (!direct) { error_code(error,"ResourceUnavailable");return -1; }
        direct->fd=-1;
        char code[S6_ERROR_CODE_SIZE]="FDAttachmentRejected";
        if (s6_fd_open(service,&direct->fd,&direct->descriptor,code,sizeof(code))) {
            free(direct);error_code(error,code);return -1;
        }
        direct->native_fd=1;*out=direct;error_code(error,"None");return 0;
    }
    pthread_once(&runtime_once, initialize);
    PyGILState_STATE gil = PyGILState_Ensure();
    s6_connection *connection = calloc(1,sizeof(*connection));
    PyObject *module=NULL, *factory=NULL, *metadata=NULL, *json=NULL, *text=NULL, *fd=NULL;
    if (!connection) { error_code(error,"ResourceUnavailable"); PyGILState_Release(gil); return -1; }
    connection->fd = -1;
    module=PyImport_ImportModule("libshadow6");
    if (module) factory=PyObject_GetAttrString(module,"Shadow6");
    if (factory) connection->facade=PyObject_CallNoArgs(factory);
    if (connection->facade) connection->handle=PyObject_CallMethod(connection->facade,"connect_handle","s",service);
    if (connection->handle) fd=PyObject_CallMethod(connection->handle,"dup_fd",NULL);
    if (fd) connection->fd=(int)PyLong_AsLong(fd);
    if (connection->fd >= 0 && !PyErr_Occurred()) metadata=PyObject_CallMethod(connection->handle,"describe",NULL);
    if (metadata) json=PyImport_ImportModule("json");
    if (json) text=PyObject_CallMethod(json,"dumps","O",metadata);
    const char *encoded = text ? PyUnicode_AsUTF8(text) : NULL;
    if (encoded && strlen(encoded) <= 65536) connection->descriptor=strdup(encoded);
    int success = connection->descriptor && !PyErr_Occurred();
    if (!success) python_error(error);
    Py_XDECREF(module); Py_XDECREF(factory); Py_XDECREF(metadata); Py_XDECREF(json); Py_XDECREF(text); Py_XDECREF(fd);
    PyGILState_Release(gil);
    if (!success) { s6_connection_destroy(connection); return -1; }
    *out=connection; error_code(error,"None"); return 0;
}
int s6_connection_fd(const s6_connection *connection) { return connection ? connection->fd : -1; }
int s6_connection_dup_fd(const s6_connection *connection) {
    if (!connection || connection->fd < 0) return -1;
    return fcntl(connection->fd,F_DUPFD_CLOEXEC,0);
}
int s6_connection_descriptor(const s6_connection *connection, char *buffer, size_t capacity, size_t *required) {
    if (!connection || !connection->descriptor || !required) return -1;
    *required=strlen(connection->descriptor)+1;
    if (!buffer || capacity < *required) return -2;
    memcpy(buffer,connection->descriptor,*required); return 0;
}
void s6_connection_destroy(s6_connection *connection) {
    if (!connection) return;
    if (connection->fd >= 0) close(connection->fd);
    if (connection->native_fd) { free(connection->descriptor);free(connection);return; }
    PyGILState_STATE gil=PyGILState_Ensure();
    PyObject *result=NULL;
    if (connection->handle) result=PyObject_CallMethod(connection->handle,"close",NULL);
    Py_XDECREF(result); PyErr_Clear();
    if (connection->facade) result=PyObject_CallMethod(connection->facade,"close",NULL); else result=NULL;
    Py_XDECREF(result); PyErr_Clear();
    Py_XDECREF(connection->handle); Py_XDECREF(connection->facade);
    PyGILState_Release(gil);
    free(connection->descriptor); free(connection);
}

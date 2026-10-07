#ifndef SHADOW6_APPLICATION_H
#define SHADOW6_APPLICATION_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define S6_APPLICATION_ABI_V1 1u
#define S6_ERROR_CODE_SIZE 96u
/* This is an application attachment ABI, never a Core wire/data ABI. */
typedef struct s6_connection s6_connection;
typedef struct { uint32_t abi_version; char code[S6_ERROR_CODE_SIZE]; } s6_error;
/* Control uses installed Python/libshadow6; data uses the returned native fd.
 * Services are operator-created and explicitly bound before this call.
 * The library does not initialize/finalize an application's Python runtime.
 * When used standalone it initializes Python once and leaves it alive.
 * Do not fork with live handles or finalize Python before destroying handles.
 */
uint32_t s6_application_abi(void);
int s6_connection_open(uint32_t abi, const char *service, s6_connection **out, s6_error *error);
/* Borrowed CLOEXEC descriptor, valid until destroy. Application synchronizes
 * data I/O against destroy. Never close a borrowed fd or store it after destroy.
 */
int s6_connection_fd(const s6_connection *connection);
/* Caller-owned CLOEXEC duplicate; shared socket queues and flags. */
int s6_connection_dup_fd(const s6_connection *connection);
/* Versioned UTF-8 JSON control metadata, copied to caller storage. required
 * includes NUL. Returns -2 for insufficient capacity, -1 for invalid arguments.
 * Never use JSON/RPC for application packets.
 */
int s6_connection_descriptor(const s6_connection *connection, char *buffer, size_t capacity, size_t *required);
/* Close only the attachment. NULL accepted. Caller must serialize destroy.
 * The Named Service remains alive. All caller-owned duplicates must be closed.
 */
void s6_connection_destroy(s6_connection *connection);
#ifdef __cplusplus
}
#endif
#endif

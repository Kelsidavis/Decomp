#ifndef REIMPL_SHIMS_H
#define REIMPL_SHIMS_H

/* Minimal shims for environments lacking platform SDKs.
 * Only used if included by your sources/tests. Safe no-ops.
 */

#ifdef _WIN32
/* If compiling on Windows with SDK, prefer real headers. */
#else
typedef void* HANDLE;
typedef const char* LPCSTR;
typedef int BOOL;
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

/* Very small subset stubs — extend as needed. */
static inline HANDLE CreateMutexA(void* lpAttr, BOOL bInitialOwner, LPCSTR lpName) { (void)lpAttr; (void)bInitialOwner; (void)lpName; return (HANDLE)0; }
static inline int CloseHandle(HANDLE h) { (void)h; return TRUE; }
#endif /* _WIN32 */

/* FMOD / audio libs placeholder */
#ifndef FMOD_SYSTEM_DEFINED
typedef void* FMOD_SYSTEM;
static inline int FMOD_System_Create(FMOD_SYSTEM* sys) { if (sys) *sys = 0; return 0; }
#endif

#endif /* REIMPL_SHIMS_H */


/* Experimental spython interpreter for Linux
 *
 * Christian Heimes <christian@python.org>
 *
 * Licensed to PSF under a Contributor Agreement.
 */
#include "Python.h"
#include "pystrhex.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <openssl/evp.h>

// 2 MB
#define MAX_PY_FILE_SIZE (2*1024*1024)

#define XATTR_NAME "user.org.python.x-spython-hash"
#define XATTR_LENGTH ((EVP_MAX_MD_SIZE * 2) + 1)


/* hash a Python bytes object */
static PyObject*
spython_hash_bytes(const char *filename, PyObject *buffer)
{
    char *buf;
    Py_ssize_t size = 0;
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;
    PyObject *result = NULL;

    if (PyBytes_AsStringAndSize(buffer, &buf, &size) == -1) {
        goto end;
    }

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        PyErr_SetString(PyExc_ValueError, "EVP_MD_CTX_new() failed");
        goto end;
    }
    if (!EVP_DigestInit(ctx, md)) {
        PyErr_SetString(PyExc_ValueError, "EVP_DigestInit SHA-256 failed");
        goto end;
    }
    if (!EVP_DigestUpdate(ctx, (const void*)buf, (unsigned int)size)) {
        PyErr_SetString(PyExc_ValueError, "EVP_DigestUpdate() failed");
        goto end;
    }
    if (!EVP_DigestFinal_ex(ctx, digest, &digest_size)) {
        PyErr_SetString(PyExc_ValueError, "EVP_DigestFinal() failed");
        goto end;
    }
    result = _Py_strhex((const char *)digest, (Py_ssize_t)digest_size);

  end:
    EVP_MD_CTX_free(ctx);
    return result;
}

static PyObject*
spython_fgetxattr(const char *filename, int fd)
{
    char buf[XATTR_LENGTH];
    Py_ssize_t size;

    size = fgetxattr(fd, XATTR_NAME, (void*)buf, sizeof(buf));
    if (size == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
        return NULL;
    }
    return PyUnicode_DecodeASCII(buf, size, "strict");
}


static PyObject*
spython_open_stream(const char *filename, int fd)
{
    struct stat sb;
    PyObject *stream = NULL;
    PyObject *iomod = NULL;
    PyObject *fileio = NULL;
    PyObject *buffer = NULL;
    PyObject *res = NULL;
    PyObject *file_hash = NULL;
    PyObject *xattr_hash = NULL;
    int cmp;

    if (fstat(fd, &sb) == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
        goto end;
    }
    /* Only open regular files */
    if (!S_ISREG(sb.st_mode)) {
        errno = EINVAL;
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
        goto end;
    }
    /* limit file size */
    if (sb.st_size > MAX_PY_FILE_SIZE) {
        errno = EFBIG;
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
        goto end;
    }

    if ((iomod = PyImport_ImportModule("_io")) == NULL) {
        goto end;
    }

    /* read file with _io module */
    fileio = PyObject_CallMethod(iomod, "FileIO", "isi", fd, "r", 0);
    if (fileio == NULL) {
        goto end;
    }
    buffer = PyObject_CallMethod(fileio, "readall", NULL);
    res = PyObject_CallMethod(fileio, "close", NULL);
    if ((buffer == NULL) || (res == NULL)) {
        goto end;
    }

    if ((file_hash = spython_hash_bytes(filename, buffer)) == NULL) {
        goto end;
    }
    if ((xattr_hash = spython_fgetxattr(filename, fd)) == NULL) {
        goto end;
    }
    cmp = PyObject_RichCompareBool(file_hash, xattr_hash, Py_EQ);
    switch(cmp) {
      case 1:
        stream = PyObject_CallMethod(iomod, "BytesIO", "O", buffer);
        break;
      case 0:
        PyErr_Format(PyExc_ValueError, "File hash mismatch: %s (%R, %R)", filename, file_hash, xattr_hash);
        goto end;
      default:
        goto end;
    }

  end:
    Py_XDECREF(buffer);
    Py_XDECREF(iomod);
    Py_XDECREF(fileio);
    Py_XDECREF(res);
    Py_XDECREF(file_hash);
    Py_XDECREF(xattr_hash);
    return stream;
}

static PyObject*
spython_open_code(PyObject *path, void *userData)
{
    PyObject *filename_obj = NULL;
    const char *filename;
    int fd = -1;
    PyObject *stream = NULL;

    if (PySys_Audit("spython.open_code", "O", path) < 0) {
        goto end;
    }

#if 0
    if (!PyUnicode_Check(path)) {
        PyErr_SetString(PyExc_TypeError, "invalid type passed to open_code");
        goto end;
    }
#endif

    if (!PyUnicode_FSConverter(path, &filename_obj)) {
        goto end;
    }
    filename = PyBytes_AS_STRING(filename_obj);

    fd = _Py_open(filename, O_RDONLY);
    if (fd < 0) {
        goto end;
    }

    stream = spython_open_stream(filename, fd);

  end:
    Py_XDECREF(filename_obj);
    if (fd < 0) {
        close(fd);
    }
    return stream;
}

int
main(int argc, char **argv)
{
    PyStatus status;
    PyConfig config;

    status = PyConfig_InitIsolatedConfig(&config);
    if (PyStatus_Exception(status)) {
        goto fail;
    }

    config.parse_argv = 1;

    // PySys_AddAuditHook(default_spython_hook, NULL);
    PyFile_SetOpenCodeHook(spython_open_code, NULL);

    status = PyConfig_SetBytesArgv(&config, argc, argv);
    if (PyStatus_Exception(status)) {
        goto fail;
    }

    status = PyConfig_Read(&config);
    if (PyStatus_Exception(status)) {
        goto fail;
    }

    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) {
        goto fail;
    }
    PyConfig_Clear(&config);

    return Py_RunMain();

  fail:
    PyConfig_Clear(&config);
    if (PyStatus_IsExit(status)) {
        return status.exitcode;
    }
    /* Display the error message and exit the process with
       non-zero exit code */
    Py_ExitStatusException(status);
}

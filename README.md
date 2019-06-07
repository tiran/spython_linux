# PEP 578 spython proof of concept for Linux

This is a highly experimental **proof of concept** implementation of
``spython`` for Linux. It uses extended file attributes to flag
permitted ``py``/``pyc`` files. The extended file attribute
``user.org.python.x-spython-hash`` contains a SHA-256 hashsum of the
file content. The ``spython`` interpreter refuses to load any Python
file that has no or an invalid hashsum.

## TODO

* Add audit logging
* Improve error reporting and exception messages
* Look for resource leaks
* Prevent piping code into the interpreter,
  ``cat code.py | spython`` should fail.
* Prevent ``spython -c 'code'``
* Restrict ``dlopen`` for extension modules and only allow the
  interpreter to load executable shared libraries on an executable
  file system (O_MAYEXEC).
* Restrict ``dlopen`` for ctypes.
* Block write access to extended file attributes. Perhaps disallow
  ``sys_setxattr``, ``sys_fsetxattr``, and ``sys_lsetxattr`` with a
  ``seccomp`` BPF rule?

## Resources

* [PEP 578](https://www.python.org/dev/peps/pep-0578/)
* [man xattr(7)](http://man7.org/linux/man-pages/man7/xattr.7.html)
* Steve's [spython](https://github.com/zooba/spython) implementation for Windows
* [O_MAYEXEC](https://lwn.net/Articles/774676/) article on LWN

# initial information about the project
AC_INIT([validate_doc],[0.1])

# check if the source folder is available
AC_CONFIG_SRCDIR([main.c])

# check for C preprocessor and compiler
AC_PROG_CC

# automake initialization (mandatory) including a check for automake API version >= 1.9
AM_INIT_AUTOMAKE([foreign])

# use the C compiler for the following checks
AC_LANG([C])

AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([assert.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# files to generate via autotools (prepare .am or .in source files)
AC_CONFIG_FILES([Makefile])

# finally this generates the Makefiles etc. for the build
AC_OUTPUT
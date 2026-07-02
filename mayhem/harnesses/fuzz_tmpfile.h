/*
 * fuzz_tmpfile.h - scratch files for the cups harnesses (mayhem layer).
 *
 * Harness scratch goes under $TMPDIR (fallback /tmp when unset or empty), created with mkstemps(),
 * never under a hardcoded directory (PORTING.md, "Scratch OUTPUT").
 */
#ifndef FUZZ_TMPFILE_H
#define FUZZ_TMPFILE_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif
#define FUZZ_TMP_PATH_MAX PATH_MAX

/*
 * Create a new, empty, uniquely named file "<$TMPDIR>/<prefix>XXXXXX<suffix>" and store its path in
 * path[size]. Returns 0 on success; -1 (path set to "") if the path does not fit or mkstemps() fails.
 */
static int
fuzz_tmpfile(char *path, size_t size, const char *prefix, const char *suffix)
{
  const char *dir = getenv("TMPDIR");
  int         n, fd;

  if (!dir || !*dir)
    dir = "/tmp";

  n = snprintf(path, size, "%s/%sXXXXXX%s", dir, prefix, suffix);
  if (n < 0 || (size_t)n >= size)
  {
    if (size)
      path[0] = '\0';
    return (-1);
  }

  if ((fd = mkstemps(path, (int)strlen(suffix))) < 0)
  {
    path[0] = '\0';
    return (-1);
  }

  close(fd);
  return (0);
}

#endif /* !FUZZ_TMPFILE_H */

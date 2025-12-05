#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
    int result;

    result = setuid(0);
    if (result != 0 ) {
      printf("could not setuid(0): %s\n", strerror(errno));
      return result;
    }

    result = setgid(0);
    if (result != 0) {
      printf("could not setguid(0): %s\n", strerror(errno));
      return result;
    }

    printf("Starting root shell...\n");
    system("/bin/bash");
    return 0;
}

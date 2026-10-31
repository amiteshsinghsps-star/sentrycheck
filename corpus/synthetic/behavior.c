// Declares a deterministic uname assertion whose observable output can differ.
#include <stdio.h>
#include <sys/utsname.h>
int main(void) { struct utsname info; if (uname(&info)) return 1; puts(info.release); return 0; }

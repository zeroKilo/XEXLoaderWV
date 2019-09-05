#include <stdio.h>
#include "mspack.h"
#include "system.h"
#include "lzx.h"
int main (int argc, char *argv[]) 
{
	int result;
	struct mspack_system *sys = mspack_default_system;
    struct mspack_file *lzxinput, *lzxoutput;
    struct lzxd_stream *lzxd;
	lzxinput = sys->open(sys, "input.bin", MSPACK_SYS_OPEN_READ);
    if (!lzxinput)
        return 1;
    lzxoutput = sys->open(sys, "output.bin", MSPACK_SYS_OPEN_WRITE);
    if (!lzxoutput)
        return 2;
    lzxd = lzxd_init(sys, lzxinput, lzxoutput, 15, 0, 100*1024*1024, 0);
    if (!lzxd)
		return 3;
    result = lzxd_decompress(lzxd, 100*1024*1024);
    lzxd_free(lzxd);
	if(result != 3)
		return 4;
	return 0;
}
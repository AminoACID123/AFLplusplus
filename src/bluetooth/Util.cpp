#include "Util.h"
#include "../../include/bluetooth.h"
#include "../../include/types.h"

#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
using namespace std;

static s32 dev_urandom_fd;
static u64 rand_seed[3];
static u32 rand_cnt;

#define ROTL(d, lrot) ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))))

void rand_init(s32 fd)
{
    dev_urandom_fd = fd;
    read(dev_urandom_fd, &rand_seed, sizeof(rand_seed));
}

static u64 rand_next() {
    u64 xp = rand_seed[0];
    rand_seed[0] = 15241094284759029579u * rand_seed[1];
    rand_seed[1] = rand_seed[1] - xp;
    rand_seed[1] = ROTL(rand_seed[1], 27);
    return xp;
}

u32 rand_below(u32 limit) {
    if (limit <= 1)
      return 0;
    if (unlikely(!rand_cnt--)) {
      read(dev_urandom_fd, &rand_seed, sizeof(rand_seed));
      rand_cnt = (100000 / 2) + (rand_seed[1] % 100000);
    }

    u64 unbiased_rnd;
    do {
      unbiased_rnd = rand_next();
    } while (unlikely(unbiased_rnd >= (UINT64_MAX - (UINT64_MAX % limit))));
    return unbiased_rnd % limit;
}

void rand_fill(u8* buf, u32 size){
    for(u32 i=0;i<size/sizeof(u32);i++)
      *((u32*)buf + i) = rand_below(UINT32_MAX);
    for(u32 i=0;i<size%sizeof(u32);i++)
      buf[size - i - 1] = rand_below(UINT8_MAX);
}

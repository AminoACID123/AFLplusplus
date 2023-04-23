#include "btfuzz_rand.h"

#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

static int dev_urandom_fd;
static u64 rand_seed[3];
static u32 rand_cnt;

#define ROTL(d, lrot) ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))))

void rand_init()
{
    dev_urandom_fd = open("/dev/urandom", O_RDONLY);
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

void rand_fill(u8* buf, u32 bytes){
    for(u32 i=0;i<bytes/sizeof(u32);i++)
      *((u32*)buf + i) = rand_below(UINT32_MAX);
    for(u32 i=0;i<bytes%sizeof(u32);i++)
      buf[bytes - i - 1] = rand_below(UINT8_MAX);
}


#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int jitshm_create(int flags, size_t size, int prot);
int jitshm_alias(int fd, int prot);

__attribute__((optimize(3)))
void* memcpy(void* dst, void* src, size_t sz)
{
    char* d = dst;
    char* s = src;
    while(sz--)
        *d++ = *s++;
    return dst;
}

int main(void* dlsym, int master, int victim, uint64_t pktopts, uint64_t kdata_base)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = 0},
        .sin_port = __builtin_bswap16(9019),
    };
    if(bind(sock, (void*)&sin, sizeof(sin)))
        return 1;
    listen(sock, 1);
    for(;;)
    {
        int sock2 = accept(sock, 0, 0);
        void* buf = mmap(0, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        size_t sz = 0;
        size_t cap = 16384;
        for(;;)
        {
            if(sz == cap)
            {
                void* buf2 = mmap(0, cap*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
                memcpy(buf2, buf, sz);
                munmap(buf, cap);
                buf = buf2;
                cap *= 2;
            }
            ssize_t chk = read(sock2, (char*)buf+sz, cap-sz);
            if(chk <= 0)
                break;
            sz += chk;
        }
        close(sock2);
        uint8_t* header = buf;
        if(header[0] != 0xeb || header[1] != 11 || header[2] != 'P' || header[3] != 'L' || header[4] != 'D')
        {
            munmap(buf, cap);
            continue;
        }
        size_t code_size;
        memcpy(&code_size, header+5, 8);
        size_t offset = (-code_size) & 0x3fff;
        int jit1 = jitshm_create(0, offset+code_size, PROT_READ|PROT_WRITE|PROT_EXEC);
        int jit2 = jitshm_alias(jit1, PROT_READ|PROT_WRITE);
        void* main_map = mmap((void*)0xc00000000, offset+code_size, PROT_READ|PROT_EXEC, MAP_SHARED|MAP_FIXED, jit1, 0);
        void* alias_map = mmap(0, offset+code_size, PROT_READ|PROT_WRITE, MAP_SHARED, jit2, 0);
        memcpy((char*)alias_map+offset, buf, code_size);
        munmap(alias_map, offset+code_size);
        char* entry = (char*)main_map + offset;
        mmap(entry+code_size, sz-code_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        memcpy(entry+code_size, (char*)buf+code_size, sz-code_size);
        munmap(buf, cap);
        ((int(*)(void*, int, int, uint64_t, uint64_t))entry)(dlsym, master, victim, pktopts, kdata_base);
    }
    return 0;
}

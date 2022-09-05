#include "gap.h"
#include <stdlib.h>

#define MAX_INPUT

static void** context;

static void** argv;

void fuzz_init(){
    context = malloc(sizeof(void*)*MAX_INPUT);
    for(int i=0;i<MAX_INPUT;i++){
        context[i] = malloc(1);
    }
    argv = malloc(sizeof(void*)*MAX_INPUT);
}

void harness1(int argc, void** argv){
    void* _i0 = argv[0];
    void* _i1 = argv[1];
    gap_connect(_i0, _i1);
}

typedef void (*fun_ptr)(char**);

fun_ptr FUZZ_LIST[] = {
    
};

/*
filed                   bytes
----------------------------------
harness_id              4
arg count               4
arg1_len                4
arg1_use_context        4
arg1_data               --


*/
void execute(char* test, int len){
    int pos = 0;

    while(1){

        if(pos >= len)
            return;

        int id = *(int*)(test + (pos+=sizeof(int)));
        fun_ptr fun = FUZZ_LIST[id];
        int args = *(int*)(test + (pos+=sizeof(int)));
        pos += sizeof(int);
        for(int i=0;i<args;i++){
            int len = *(int*)(test + (pos+=sizeof(int)));
            int cxt = *(int*)(test + (pos+=sizeof(int)));
            if(cxt != -1){
                argv[i] = context[cxt];
            }else{
                argv[i] = test + (pos += len);
            }
        }
    }
}


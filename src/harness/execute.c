
extern char arg_in[];
extern char arg_out[];
extern char context[];

typedef void (*fun_ptr)(char **, char **);
extern fun_ptr FUZZ_LIST[];

/*
field                   bytes
----------------------------------
harness_idx             4
arg_in_count            4
arg1_idx                4
arg1_len                4
arg1_data               --
arg_out_count           4
arg1_idx                4

*/

void execute_api(char *buf, int size) {

  int harness_idx = *(int*)buf;

  int arg_in_count, arg_out_count;

  arg_in_count = *(int*)(buf + 4);

  int pos = buf + 8;

  for(int i=0;i<arg_in_count;i++){
    int arg_idx = *(int*)(buf + pos);
    pos += 4;
    if (arg_idx == -1) {
      int len = *(int *)(buf + pos);
      pos += sizeof(int);
      arg_in[i] = buf + pos;
      pos += len;
    } else {
      arg_in[i] = context[arg_idx];
    }
  }

  arg_out_count = *(int *)(buf + pos);
  pos += 4;

  for(int i=0;i<arg_out_count;i++){
      int idx = *(int *)(buf + pos);
      pos += sizeof(int);
      arg_out[i] = context[idx];
  }
  
  FUZZ_LIST[harness_idx](arg_in, arg_out);
}

void execute_hci(char* buf, int size);

void execute_one(char* buf, int size){
    if(buf[0] == API)
      execute_api(buf + 1, size);
    else
      execute_hci(buf + 1, size);
}
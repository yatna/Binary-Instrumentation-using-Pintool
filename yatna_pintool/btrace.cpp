/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include <iostream>
#include <fstream>
#include <map>
#include <fcntl.h>
#include <sys/mman.h>
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;
using std::vector;
using std::hex;
using std::dec;

ofstream OutFile;

static INT32 numThreads = 0;
static  TLS_KEY tls_key = INVALID_TLS_KEY;

class Thread_data{
  public:
    bool inside_syscall;
    int entrycount;
    int exitcount;
    int prev_call;

    Thread_data(){
        inside_syscall=false;
        entrycount=0;
        exitcount=0;
        prev_call=0;
    }
};

vector<string> syscall_names(500,"");

void ins_read_write(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    string s = string((char *)ecx,0, 15);
    if(s.size()==15)s+="...";
    string p ="\"";
    for(unsigned int i=0;i<s.size();i++){
        if(s[i]=='\n')p+="\\n";
        else if(s[i]=='\t')p+="\\t";
        else p+=s[i];
    }
    p+="\"";

    OutFile << func<<"("<<(unsigned int)ebx << " , " << p << " , "<<(size_t)edx<<")"; 
}
void print_open_flag(int flags){
    string ans;
    if(flags & O_RDWR)ans="O_RDWR";
    else if(flags & O_WRONLY)ans="O_WRONLY";
    else ans="O_RDONLY";
    int f[] = {O_APPEND, O_ASYNC, O_CLOEXEC,O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL,
     O_LARGEFILE, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH , O_SYNC, O_TMPFILE, O_TRUNC};
    const char * f_name[] = {"O_APPEND", "O_ASYNC", "O_CLOEXEC","O_CREAT", "O_DIRECT", "O_DIRECTORY",
     "O_DSYNC","O_EXCL", "O_LARGEFILE", "O_NOCTTY", "O_NOFOLLOW", "O_NONBLOCK", "O_PATH" ,
      "O_SYNC", "O_TMPFILE","O_TRUNC"};
     for(int i=0; i<16;i++){
        if(flags&f[i])ans+=string("|") + string(f_name[i]);
     }
     OutFile<<ans;
}
void ins_open(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    const char * s = (char *)ebx;

    OutFile << func<<"("<<s << " , ";
    print_open_flag(ecx); 
    OutFile<< " , "<<(int)edx<<")"; 
}
void ins_close(const CONTEXT * ctxt, string func){
    ADDRINT ebx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    OutFile << func<<"("<<(unsigned int)ebx<<")"; 
}
void print_access_mode(int ecx){
    string ans="";
    if(ecx==F_OK){
        OutFile<<"F_OK";
        return;
    }
    int p[] = {R_OK, W_OK, X_OK};
    const char * p_name[] = {"R_OK", "W_OK", "X_OK"};
    for(int i=0; i<3;i++){
        if(ecx&p[i])ans+=string(p_name[i]) + string("|");
     }
     ans.pop_back();
     OutFile<<ans;

}
void ins_access(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    const char * s = (char *)ebx;
 
    OutFile << func<<"("<<s<<" , ";
    print_access_mode(ecx);
    OutFile<<")"; 
}
void ins_brk(const CONTEXT * ctxt, string func){
    ADDRINT ebx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));

    OutFile << func<<"(";
    (ebx==0)?(OutFile)<<"NULL":(OutFile)<<(void *)ebx;
    OutFile<<")"; 
}
void ins_ioctl(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));

    OutFile << func<<"("<< (int)ebx  << " , " << (int)ecx << " , (struct address)"<<(void *)edx<<")"; 
}
void ins_munmap(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));

    OutFile << func<<"(0x"<<hex<<(unsigned long)ebx<<dec<<" , "<<(size_t)ecx<<")"; 
}
void print_mprotect_flag(int flags){
    string ans="";
    
    int f[] = {PROT_NONE, PROT_READ, PROT_WRITE,PROT_EXEC, PROT_SEM,
     PROT_GROWSUP, PROT_GROWSDOWN};
    const char * f_name[] = {"PROT_NONE", "PROT_READ", "PROT_WRITE","PROT_EXEC", "PROT_SEM"
    ,"PROT_GROWSUP", "PROT_GROWSDOWN"};
     for(int i=0; i<7;i++){
        if(flags&f[i])ans+=string(f_name[i]) + string("|");
     }
     if(ans!="")ans.pop_back();
     OutFile<<ans;
}
void ins_mprotect(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));

    OutFile << func<<"("<<(void *)ebx<<" , "<<(size_t)ecx<<" , ";
    print_mprotect_flag(edx);
    OutFile<<")"; 
}
void print_prot(int prot){
    string ans="";
    int p[] = {PROT_EXEC, PROT_READ, PROT_WRITE, PROT_NONE};
    const char * p_name[] = {"PROT_EXEC", "PROT_READ", "PROT_WRITE", "PROT_NONE"};
    
    for(int i=0;i<4;i++){
         if(prot&p[i])ans+= string(p_name[i]) + string("|");
    }
    if(ans=="")ans="PROT_NONE|";
    ans.pop_back();
    OutFile<<ans;
}
void print_mmap_flag(int prot){
    string ans="";
    int p[] = {MAP_SHARED, MAP_PRIVATE, MAP_32BIT, MAP_ANONYMOUS, MAP_DENYWRITE,
        MAP_EXECUTABLE, MAP_FILE, MAP_FIXED, MAP_GROWSDOWN, MAP_HUGETLB,MAP_HUGE_2MB,  MAP_LOCKED,
        MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE , MAP_STACK , MAP_UNINITIALIZED};

    const char * p_name[] = {"MAP_SHARED", " MAP_PRIVATE", " MAP_32BIT", 
    " MAP_ANONYMOUS", " MAP_DENYWRITE", "  MAP_EXECUTABLE", " MAP_FILE", " MAP_FIXED",
    " MAP_GROWSDOWN", " MAP_HUGETLB", "MAP_HUGE_2MB", "  MAP_LOCKED", 
    " MAP_NONBLOCK", " MAP_NORESERVE", "MAP_POPULATE", " MAP_STACK", "MAP_UNINITIALIZED"};
    
    for(int i=0;i<17;i++){
         if(prot&p[i])ans+=string(p_name[i])+ string("|");
    }
    if(ans=="")ans+="|";
    ans.pop_back();
    OutFile<<ans;
}
void ins_mmap2(const CONTEXT * ctxt, string func){ 

    ADDRINT ebx,ecx,edx,esi,edi,ebp;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    PIN_GetContextRegval(ctxt, REG_ESI, reinterpret_cast<UINT8*>(&esi));
    PIN_GetContextRegval(ctxt, REG_EDI, reinterpret_cast<UINT8*>(&edi));
    PIN_GetContextRegval(ctxt, REG_EBP, reinterpret_cast<UINT8*>(&ebp));
  
    OutFile << func<<"("<<(void *)ebx<<" , "<<(size_t)ecx<<" , ";
    print_prot(edx);
    OutFile<<" , ";
    print_mmap_flag(esi);
    OutFile<<" , "<<(long)edi<<" , "<<(long)ebp<<")"; 

}
void ins_fstat64(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));

    OutFile << func<<"("<<(unsigned long)ebx<<" , (struct address)"<<(void *)ecx<<")"; 
}
void ins_set_thread_area(const CONTEXT * ctxt, string func){
    ADDRINT ebx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));

    OutFile << func<<"( (struct address)"<<(void *)ebx<<")"; 
}
void ins_exit_group(const CONTEXT * ctxt, string func){
    ADDRINT ebx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));

    OutFile << func<<"("<<(int)ebx<<")"; 
}
void ins_uname(const CONTEXT * ctxt, string func){
    ADDRINT ebx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    OutFile << func<<"(  (struct address)"<<(void *)ebx<<")"; 
}
void ins_rt_sigaction(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx,esi;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    PIN_GetContextRegval(ctxt, REG_ESI, reinterpret_cast<UINT8*>(&esi));

    OutFile << func<<"("<<(unsigned long)ebx<<" , (struct address)"<<(void *)ecx<<" , "
    <<(void *)edx<<" , "<<(size_t)esi<<")"; 
}
void ins_rt_sigprocmask(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx,esi;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    PIN_GetContextRegval(ctxt, REG_ESI, reinterpret_cast<UINT8*>(&esi));

    OutFile << func<<"("<<(unsigned long)ebx<<" , (struct address)"<<(void *)ecx<<" , "
    <<(void *)edx<<" ,"<<(size_t)esi<<")"; 
}
void ins_rt_uget_rlimit(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));

    OutFile << func<<"("<<(unsigned long)ebx<<" , (struct address)"<<(void *)ecx<<")";  
}
void ins_getdents64(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));

    OutFile << func<<"("<<(unsigned long)ebx<<" , (struct address)"<<(void *)ecx<<" , "<<
    (unsigned int)edx<<")"; 
}
void ins_set_tid_address(const CONTEXT * ctxt, string func){
    ADDRINT ebx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    OutFile << func<<"("<<(void *)ebx<<")"; 
}
void ins_statfs64(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    char * s = (char*)ebx;
    OutFile << func<<"("<<s<<" , "<<(int)ecx<<" , "
    <<(void *)edx<<")"; 
}
void ins_set_robust_list(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));

    OutFile << func<<"( "<<(void *)ebx<<" , "<<( unsigned int)ecx<<")"; 
}
void ins_poll(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx,edx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    PIN_GetContextRegval(ctxt, REG_EDX, reinterpret_cast<UINT8*>(&edx));
    OutFile << func<<"( (struct address)"<<(void *)ebx<<" , "<<(int)ecx<<" , "
    <<(long )edx<<")"; 
}
void ins_stat64(const CONTEXT * ctxt, string func){
    ADDRINT ebx,ecx;
    PIN_GetContextRegval(ctxt, REG_EBX, reinterpret_cast<UINT8*>(&ebx));
    PIN_GetContextRegval(ctxt, REG_ECX, reinterpret_cast<UINT8*>(&ecx));
    char * s = (char *)ebx;
    OutFile << func<<"( "<<s<<" , (struct address)"<<( void *)ecx<<")"; 
}
void ins_futex(const CONTEXT * ctxt, string func){
    
    OutFile << func; 
}

// This function is called before every block
VOID syscall_start(const CONTEXT * ctxt, THREADID threadid){
    ADDRINT eax;
    PIN_GetContextRegval(ctxt, REG_EAX, reinterpret_cast<UINT8*>(&eax));
    Thread_data* td = static_cast<Thread_data*>(PIN_GetThreadData(tls_key, threadid));
    td->entrycount++;
    td->prev_call=eax;
    if(eax==3)ins_read_write(ctxt,"Read");
    else if(eax==4)ins_read_write(ctxt,"Write");
    else if(eax==5)ins_open(ctxt,"Open");
    else if(eax==6)ins_close(ctxt,"Close");
    else if(eax==33)ins_access(ctxt,"Access");
    else if(eax==45)ins_brk(ctxt,"brk");
    else if(eax==54)ins_ioctl(ctxt,"ioctl");
    else if(eax==91)ins_munmap(ctxt,"munmap");
    else if(eax==122)ins_uname(ctxt,"uname");
    else if(eax==125)ins_mprotect(ctxt,"mprotect");
    else if(eax==174)ins_rt_sigaction(ctxt,"rt_sigaction");
    else if(eax==175)ins_rt_sigprocmask(ctxt,"rt_sigprocmask");
    else if(eax==191)ins_rt_uget_rlimit(ctxt,"ugetrlimit");
    else if(eax==192)ins_mmap2(ctxt, "mmap2");
    else if(eax==197)ins_fstat64(ctxt,"fstat64");
    else if(eax==220)ins_getdents64(ctxt,"getdents64");
    else if(eax==243)ins_set_thread_area(ctxt,"set_thread_area");
    else if(eax==252)ins_exit_group(ctxt,"exit_group");
    else if(eax==258)ins_set_tid_address(ctxt,"set_tid_address");
    else if(eax==268)ins_statfs64(ctxt,"statfs64");
    else if(eax==311)ins_set_robust_list(ctxt,"set_robust_list");

    else if(eax==168)ins_poll(ctxt,"poll");
    else if(eax==195)ins_stat64(ctxt,"stat64");
    else if(eax==240)ins_futex(ctxt,"futex");
    else OutFile<< "some_unimplemented_system_call(...params...)";

    td->inside_syscall = true;
}
void print_errno(int err){
    string ans;
    err*=-1;
    int p[]= {EACCES, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EROFS,EFAULT, EINVAL, EIO, ENOMEM,
     ETXTBSY};
    const char * p_names[]= {"EACCES", "ELOOP", "ENAMETOOLONG", "ENOENT (No such file or directory)", 
    "ENOTDIR", "EROFS","EFAULT", "EINVAL", "EIO", "ENOMEM", "ETXTBSY"};
     for(int i=0;i<11;i++){
        if(err==p[i]){
            OutFile<<p_names[i];
            return;
        }
     }
     OutFile<<"ERRNO: "<<err;
}
VOID syscall_end(const CONTEXT * ctxt, THREADID threadid){  
     Thread_data* td = static_cast<Thread_data*>(PIN_GetThreadData(tls_key, threadid));
    if(td->inside_syscall){
        ADDRINT ret;
        PIN_GetContextRegval(ctxt, REG_EAX, reinterpret_cast<UINT8*>(&ret));
        td->exitcount++;
        if(td->prev_call==45 || td->prev_call==192){
            OutFile <<" = " << (void *)ret<<endl;
        }
        else{
            if((int)ret>=0)
                OutFile <<" = " << (int)ret<<endl;
            else{
                OutFile<<" = "<<-1<<"    ";
                print_errno((int)ret);
                OutFile<<endl;
            }
        }
        td->inside_syscall = false;
    } 
}


VOID Trace(TRACE trace, VOID *v)
{
    
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS firstIns = BBL_InsHead(bbl); 
        INS_InsertCall(firstIns, IPOINT_BEFORE, (AFUNPTR)syscall_end,
                IARG_CONST_CONTEXT,IARG_THREAD_ID, IARG_END);

        INS lastIns = BBL_InsTail(bbl); 
        if(INS_IsSyscall(lastIns)){
            INS_InsertCall(lastIns, IPOINT_BEFORE, (AFUNPTR)syscall_start,
                IARG_CONST_CONTEXT,IARG_THREAD_ID,IARG_END);
        }  
        
    }
   
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "out_btrace", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    OutFile.close();
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    Thread_data* td = new Thread_data;
    numThreads++;

    if (PIN_SetThreadData(tls_key, td, threadid) == FALSE)
    {
        cerr << "Failed in ThreadStart" << endl;
        PIN_ExitProcess(1);
    }
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    OutFile<<endl<<endl;
    Thread_data* td = static_cast<Thread_data*>(PIN_GetThreadData(tls_key, threadIndex));
    OutFile << "Thread " << threadIndex << " : "<<" Entry Count= "<<
    td->entrycount<<" | Exit Count= "<<td->exitcount<<endl;
    delete td;
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of BBL BLOCKS executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    syscall_names[0] = "restart_syscall";
    syscall_names[1] = "exit";
    syscall_names[2] = "fork";
    syscall_names[3] = "read";
    syscall_names[4] = "write";
    syscall_names[5] = "open";
    syscall_names[6] = "close";
    syscall_names[33] = "access";
    syscall_names[45] = "brk";
    syscall_names[54] = "ioctl";
    syscall_names[90] = "mmap";
    syscall_names[91] = "munmap";
    syscall_names[106] = "stat";
    syscall_names[107] = "lstat";
    syscall_names[108] = "fstat";
    syscall_names[122] = "uname";
    syscall_names[125] = "mprotect";
    syscall_names[174] = "rt_sigaction";
    syscall_names[175] = "rt_sigprocmask";
    syscall_names[192] = "mmap2";
    syscall_names[191] = "uget_rlimit";
    syscall_names[197] = "fstat64";
    syscall_names[220] = "getdents64";
    syscall_names[243] = "set_thread_area";
    syscall_names[252] = "exit_group";
    syscall_names[258] = "set_tid_address";
    syscall_names[268] = "statfs64";
    syscall_names[311] = "set_robust_list";

    syscall_names[168] = "poll";
    syscall_names[195] = "stat64";
    syscall_names[240] = "futex";
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "MAX_CLIENT_TLS_KEYS limit exceeded" << endl;
        PIN_ExitProcess(1);
    }

    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

     // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    // Register Fini to be called when thread exits.
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

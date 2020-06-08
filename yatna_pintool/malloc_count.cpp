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


#include "pin.H"
#include <iostream>
#include <fstream>
using std::hex;
using std::cerr;
using std::string;
using std::ios;
using std::endl;

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif

static INT32 numThreads = 0;
static  TLS_KEY tls_key = INVALID_TLS_KEY;
std::ofstream OutFile;


class Thread_data{
  public:
    UINT64 total_size;
    UINT64 prev_size;
    int total_count;
    int error_count;
    Thread_data(){
        total_size = 0;
        prev_size = 0;
        total_count = 0;
        error_count =0;
    }
};


KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "out_malloc_count", "specify trace file name");


VOID MallocBefore(CHAR * name, ADDRINT size, THREADID threadid)
{
    Thread_data* td = static_cast<Thread_data*>(PIN_GetThreadData(tls_key, threadid));
    td->total_count++;
    td->total_size+=size;
    td->prev_size=size;
}

VOID MallocAfter(ADDRINT ret,  THREADID threadid)
{
    Thread_data* td = static_cast<Thread_data*>(PIN_GetThreadData(tls_key, threadid));
    //if malloc returned error it means memory was not allocated so substract
    if(ret<0){
        td->error_count++;
        td->total_size-=td->prev_size;
    }
}

   
VOID Image(IMG img, VOID *v)
{

    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,IARG_ADDRINT, MALLOC, 
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    numThreads++;
    Thread_data* td = new Thread_data;
    if (PIN_SetThreadData(tls_key, td, threadid) == FALSE)
    {
        cerr << "Failed in ThreadStart" << endl;
        PIN_ExitProcess(1);
    }
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    Thread_data* td = static_cast<Thread_data*>(PIN_GetThreadData(tls_key, threadIndex));
    OutFile << " Thread [" <<threadIndex<< "] : MALLOC_CALLS_MADE="<<td->total_count<<
    " |  TOTAL_SIZE_ALLOCATED="<<td->total_size<<" |  TOTAL_UNSUCCESSFUL_CALLS(returned error)="
    <<td->error_count<<endl<<endl;
    delete td;
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    cerr << "This tool produces a trace of calls to malloc." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "MAX_CLIENT_TLS_KEYS limit exceeded" << endl;
        PIN_ExitProcess(1);
    }
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(Image, 0);

    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    // Register Fini to be called when thread exits.
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

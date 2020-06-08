#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

ofstream OutFile;

static INT32 numThreads = 0;
static  TLS_KEY tls_key = INVALID_TLS_KEY;
UINT32 stackPivotOffset = 0xffff;

class Thread_data{
  private:
    ADDRINT max_addr;
    ADDRINT min_addr;
    int diff;
  public:
    Thread_data(){
        max_addr = 0;
        min_addr = 0xffffffff;
        diff = 0;
    }
    void set_stack_lower_boundary(ADDRINT esp){
        if(min_addr > stackPivotOffset && min_addr<0xffffff00 
            && esp<min_addr - stackPivotOffset){
            OutFile<<"Stack Pivoting Detected...aborting"<<endl;
            OutFile.close();
            abort();
        }
        min_addr = (esp<min_addr)?esp:min_addr;
    }
    void set_stack_upper_boundary(ADDRINT esp){
        if(max_addr>stackPivotOffset && max_addr<(0xffffff00) &&
         esp>max_addr + 0xff){
            OutFile<<"Stack Pivoting Detected... aborting"<<endl;
            OutFile.close();
            abort();
        }
        max_addr = (esp>max_addr)?esp:max_addr;
    }
    void set_diff(){
        diff = max_addr - min_addr;
    }
    int get_diff(){return diff;}
};


VOID stack_size(const CONTEXT * ctxt,  THREADID threadid) { 
    Thread_data* td = static_cast<Thread_data*>(PIN_GetThreadData(tls_key, threadid));
    ADDRINT esp;
    PIN_GetContextRegval(ctxt, REG_ESP, reinterpret_cast<UINT8*>(&esp));
    td->set_stack_lower_boundary(esp);
    td->set_stack_upper_boundary(esp);
    td->set_diff();
}
    
VOID Instruction(INS inst, VOID *v)
{         
    if(INS_RegWContain(inst,REG_ESP) && INS_IsValidForIpointAfter(inst)){
        INS_InsertCall(inst,IPOINT_AFTER,AFUNPTR(stack_size),IARG_CONST_CONTEXT,IARG_THREAD_ID,
            IARG_END);
    }
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "out_stack", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    OutFile.setf(ios::showbase);
    OutFile.close();
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
    OutFile << "Stack Size for Thread ("<<threadIndex<< ") : "<<td->get_diff()<<endl;
    OutFile<< "NO STACK PIVOTING DETECTED FOR THREAD "<<threadIndex<<endl<<endl;
    delete td;
}


INT32 Usage()
{
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "MAX_CLIENT_TLS_KEYS limit exceeded" << endl;
        PIN_ExitProcess(1);
    }

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

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

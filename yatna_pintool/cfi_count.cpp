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
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

ofstream OutFile;
std::ostream * out = &cerr;
PIN_LOCK pinLock;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 direct_ctf = 0;
static UINT64 indirect_ctf = 0;
static UINT64 other_ctf = 0;

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&pinLock, threadid+1);
    PIN_ReleaseLock(&pinLock);
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    PIN_GetLock(&pinLock, threadid+1);
    PIN_ReleaseLock(&pinLock);
}

// This function is called before every block
VOID PIN_FAST_ANALYSIS_CALL direct(THREADID threadid) { 
    PIN_GetLock(&pinLock, threadid+1);
    direct_ctf++;
    PIN_ReleaseLock(&pinLock);
}
VOID PIN_FAST_ANALYSIS_CALL indirect(THREADID threadid) {
    PIN_GetLock(&pinLock, threadid+1);
    indirect_ctf++;
    PIN_ReleaseLock(&pinLock);
}
VOID PIN_FAST_ANALYSIS_CALL other(THREADID threadid) {
    PIN_GetLock(&pinLock, threadid+1);
    other_ctf++;
    PIN_ReleaseLock(&pinLock);
}

VOID Trace(TRACE trace, VOID *v)
{
    
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS lastIns = BBL_InsTail(bbl);   
        if( INS_IsDirectControlFlow(lastIns)){
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)direct, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_END);
        }
        else if(INS_IsRet (lastIns) || INS_IsIndirectControlFlow (lastIns)){
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)indirect,IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_END);
        }
        else
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)other,IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_END);
    }
   
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "out_cfi_count", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    // OutFile.setf(ios::showbase);
    // OutFile << "Count of BBL Blocks - " << bbl_count << endl;
    // OutFile.close();

    OutFile <<  "Number of Direct CTFs: " << direct_ctf  << endl;
    OutFile <<  "Number of Indirect CTFs: " << indirect_ctf  << endl;
    OutFile <<  "Number of Other CTFs: " << other_ctf  << endl;
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
    PIN_InitLock(&pinLock);
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

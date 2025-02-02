#include <iostream>
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

//Purpose of this tool is  to check  if  a.etl trace file contains  event  from Microsoft - Windows - NDIS - PacketCapture(network capture packets)
//if  the trace file given contains  such events, it  can be  further processed  into pcap format.

    // Microsoft-Windows-NDIS-PacketCapture
    // 2ED6006E-4729-4609-B423-3EE7BCD678EF
int g_maxevents = 50000; // number  of  event we   process max.  from the etl file
int g_processedevents = 0;  // number of  already processed  events 
bool g_ispacketcapture = false;  // true  when  we  detect  events  from  ndiscap
bool g_overflow = false; // true  when  we  hit  the maximum number  of  events  to parse  as  defined by g_maxevents
// event processing callbacks:
VOID WINAPI EventRecordCallback(_In_ PEVENT_RECORD pEvent);  
ULONG WINAPI BufferCallback(_In_ PEVENT_TRACE_LOGFILE Buffer);

int wmain()
{
    if (__argc != 2)
    {
        std::cout << "invalid  usage \n  usage: isnetcap.exe <pathtoETLFile> \n\t returns 3 if  ETL has  networkcapture buffers , returns 0  if  it  does not" << std::endl;
        std::cout << "argc is: " << __argc << std::endl;
        return 0;
    }
    
    ULONG status = ERROR_SUCCESS;
    EVENT_TRACE_LOGFILE logfile;
    TRACE_LOGFILE_HEADER* pHeader = &logfile.LogfileHeader;
    TRACEHANDLE hTrace = 0;
    ZeroMemory(&logfile, sizeof(EVENT_TRACE_LOGFILE));
    logfile.BufferCallback = BufferCallback;
    logfile.EventRecordCallback = EventRecordCallback;
    logfile.LogFileName = __wargv[1];
    std::wstring logname;
    logname = logfile.LogFileName;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    hTrace = OpenTrace(&logfile);
    if ((TRACEHANDLE)INVALID_HANDLE_VALUE == hTrace)
    {
        wprintf(L"OpenTrace failed with %lu\n", GetLastError());
        return 0;
    }
    status = ProcessTrace(&hTrace, 1, 0, 0);
 
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
    {
        wprintf(L"ProcessTrace failed with %lu\n", status);
        return 0;
    }

    if (g_ispacketcapture == true && g_overflow == false)
    {
        std::wcout << "this trace  contains network packets: " << logname;
        std::wcout << "first captured  packet seen in event: " << g_processedevents   << std::endl;
        return 3;
        
    }
    if (g_ispacketcapture == false || g_overflow == true)
    {
        std::wcout << "this trace  does NOT contain network packets in the first 10k events: " << logname << std::endl;
        return 0;
        
    }

    
}




VOID WINAPI EventRecordCallback(  _In_ PEVENT_RECORD  pEvent)
{
    g_processedevents++;
   // std::cout << "processing event no. " << g_processedevents << std::endl;
  
    if (pEvent->EventHeader.ProviderId.Data1 == 0x2ED6006E && pEvent->EventHeader.ProviderId.Data2 == 0x4729 && pEvent->EventHeader.ProviderId.Data3 == 0x4609)
    {
        
        g_ispacketcapture = true;
    }
    if (g_processedevents > g_maxevents)
    {
        g_overflow = true;
        g_ispacketcapture = true; // this is set  to  true when  we  hit the max number  of  events  to be  parsed , only  to  indicated  stop processing the file  further inside buffercallback, 
    }
}

ULONG WINAPI BufferCallback(
    _In_ PEVENT_TRACE_LOGFILE Buffer
)
{
    if (g_ispacketcapture == false)
    {
        return true;
    }
    else { return false; };
 
    
}
#include <windows.h>
#include <TlHelp32.h>

#define MSGBOX_CAPTION "Error"

DWORD dwAddress1Diff = 0x00000000;
DWORD dwAddress2Diff = 0x000000AA;
DWORD dwAddress3Diff = 0x000000FD;
DWORD dwAddress4Diff = 0x00000118;

BYTE Signature[] = {0x75,0x64,0x6A,0x10};

BYTE Replacement1[] = {0xEB};
BYTE Replacement2[] = {0xEB};
BYTE Replacement3[] = {0x90,0x90};
BYTE Replacement4[] = {0x90,0x90};
/*
struct ModuleInfo {
	DWORD dwStartAddress;
	DWORD dwEndAdress;
} Module;
*/
class ModuleInfo {
    public:
	DWORD dwStartAddress;
	DWORD dwEndAdress;
} Module;

int GetModuleInfo(DWORD dwProcessIdentifier,TCHAR *lpszModuleName) {
	int Code=0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,dwProcessIdentifier);

	if(hSnapshot != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 ModuleEntry32 = {0};
		ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
		if(Module32First(hSnapshot,&ModuleEntry32)) {
			do {
				if(strcmp(ModuleEntry32.szModule,lpszModuleName) == 0) {
					Module.dwStartAddress = (DWORD)ModuleEntry32.modBaseAddr;
					Module.dwEndAdress = (DWORD)(Module.dwStartAddress+ModuleEntry32.modBaseSize);
					Code=1;
					break;
				}
			} while(Module32Next(hSnapshot,&ModuleEntry32));
		}

		CloseHandle(hSnapshot);
	}

	return Code;
}

int main(int argc,char *argv[]) {
	char szName[32];
	memset(szName,0,sizeof(szName));

	if(!strcmpi(argv[1],"-name") && argv[2]!='\0') {
		strncat(szName,argv[2],sizeof(szName)-1);
	} else {
		strncat(szName,"Registered",sizeof(szName)-1);
	}

	char szLicense[32];
	memset(szLicense,0,sizeof(szLicense));
	strncat(szLicense,"0000-0000-0000-0000",sizeof(szLicense)-1);
	char szValidated[32];
	memset(szValidated,0,sizeof(szValidated));
	strncat(szValidated,"0000-0000-0000-0000",sizeof(szValidated)-1);

	HKEY hKey;
	RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\mIRC\\UserName",0,NULL,REG_OPTION_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,NULL);
	RegSetValueEx(hKey,NULL,0,REG_SZ,(unsigned char*)szName,strlen(szName));
	RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\mIRC\\License",0,NULL,REG_OPTION_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,NULL);
	RegSetValueEx(hKey,NULL,0,REG_SZ,(unsigned char*)szLicense,strlen(szLicense));
	RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\mIRC\\Validated",0,NULL,REG_OPTION_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,NULL);
	RegSetValueEx(hKey,NULL,0,REG_SZ,(unsigned char*)szValidated,strlen(szValidated));
	RegCloseKey(hKey);

	typedef BOOL (*DEBUGACTIVEPROCESSSTOP)(DWORD);
	DEBUGACTIVEPROCESSSTOP _DebugActiveProcessStop;
	HMODULE hK32 = LoadLibrary("kernel32.dll");
	_DebugActiveProcessStop=(DEBUGACTIVEPROCESSSTOP)GetProcAddress(hK32,"DebugActiveProcessStop");

	STARTUPINFO StartupInfo = {};
	PROCESS_INFORMATION ProcInfo = {};
	if(!CreateProcess("mirc.exe",0,0,FALSE,0,DEBUG_ONLY_THIS_PROCESS,0,0,&StartupInfo,&ProcInfo)) {
		MessageBox(0,"Failed to open mirc.exe\rEnsure loader is within mIRC installation folder",MSGBOX_CAPTION,MB_ICONERROR);
		return 0;
	}

	DEBUG_EVENT DebugEvent;
	bool bReady2Exit = false;
	while(!bReady2Exit) {
		memset(&DebugEvent,0,sizeof(DEBUG_EVENT));
		if(WaitForDebugEvent(&DebugEvent,1000)) {
			if(DebugEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
				if(GetModuleInfo(ProcInfo.dwProcessId,(char*)&"mirc.exe")) {
					DWORD dwCurrentAddress = Module.dwStartAddress;
					BYTE *MemValue;
					int iSigLen=sizeof(Signature);
					while(dwCurrentAddress < Module.dwEndAdress) {
						ReadProcessMemory(ProcInfo.hProcess,(void*)dwCurrentAddress,&MemValue,iSigLen,NULL);

						if(memcmp(Signature,&MemValue,iSigLen) == 0) {
							if(WriteProcessMemory(ProcInfo.hProcess,(void*)(dwCurrentAddress+dwAddress1Diff),&Replacement1,sizeof(Replacement1),NULL) == 0
							|| WriteProcessMemory(ProcInfo.hProcess,(void*)(dwCurrentAddress+dwAddress2Diff),&Replacement2,sizeof(Replacement2),NULL) == 0
                            || WriteProcessMemory(ProcInfo.hProcess,(void*)(dwCurrentAddress+dwAddress3Diff),&Replacement3,sizeof(Replacement3),NULL) == 0
                            || WriteProcessMemory(ProcInfo.hProcess,(void*)(dwCurrentAddress+dwAddress4Diff),&Replacement4,sizeof(Replacement4),NULL) == 0) {
								MessageBox(0,"Memory write failed\rEnsure you are using mIRC v7.36",MSGBOX_CAPTION,MB_ICONERROR);
								return 0;
							}

							_DebugActiveProcessStop(ProcInfo.dwProcessId);
							bReady2Exit=true;
							break;
						}

						dwCurrentAddress++;
					}
				}
			}

			ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
		}
	}

	CloseHandle(ProcInfo.hProcess);
	CloseHandle(ProcInfo.hThread);

	return 0;
}

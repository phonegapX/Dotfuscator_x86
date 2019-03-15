// test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "test.h"
#include "..\main\Dotfuscator.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// The one and only application object

CWinApp theApp;

using namespace std;

void LoopDirectory(const char* szPath, LPSTORAGE pStg)
{
    START_MUTATE()

	WIN32_FIND_DATA stData;
    char szNewPath[MAX_PATH];

	strcpy(szNewPath, szPath);
	if (szNewPath[lstrlen(szNewPath)-1] != '\\') 
		strcat(szNewPath, "\\");
    strcat(szNewPath, "*.*");

	HANDLE hSearch = ::FindFirstFile(szNewPath, &stData);

	if (hSearch == INVALID_HANDLE_VALUE)
		return;

	do
	{
		if (!strcmp(stData.cFileName, "..") || !strcmp(stData.cFileName, ".")) 
			continue;
		
		if (stData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
		{	//是目录
			strcpy(szNewPath, szPath);
			if (szNewPath[lstrlen(szNewPath)-1] != '\\') 
				strcat(szNewPath, "\\");
			strcat(szNewPath, stData.cFileName);
			strcat(szNewPath, "\\");
	        LoopDirectory(szNewPath, NULL);
		}
		else
		{	//是文件
			strcpy(szNewPath, szPath);
			strcat(szNewPath, stData.cFileName);
			printf("%s\n", szNewPath);
		}
	}
	while (::FindNextFile(hSearch, &stData));

    END_MUTATE()
}



int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;
	
	// initialize MFC and print and error on failure
	if (!AfxWinInit(::GetModuleHandle(NULL), NULL, ::GetCommandLine(), 0))
	{
		// TODO: change error code to suit your needs
		cerr << _T("Fatal Error: MFC initialization failed") << endl;
		nRetCode = 1;
	}
	else
	{
		// TODO: code your application's behavior here.
		CString strHello;
		strHello.LoadString(IDS_HELLO);
		cout << (LPCTSTR)strHello << endl;
	}

	LoopDirectory("I:\\ARMTranslator", NULL);
	
	return nRetCode;
}



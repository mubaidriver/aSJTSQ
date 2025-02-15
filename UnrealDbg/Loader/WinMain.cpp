#include "WinMain.h"
#include "Symbols.h"

#define TIMER_PROGRESSBAR 1
#define TIMER_TEXT 2

const int MAX_DOTS = 3;
int dotCount = 0;
std::wstring baseText1(L"�������ڳ�ʼ����");
std::wstring modText;
std::wstring displayText;
int currentTextIndex = 0; // ��ǰ���Ƶ��ı�����

int nWidth = 0;
int progress = 0; // �������ĵ�ǰ����
int tickcount = 0;


HWND g_hwnd;
std::wstring curdir;

void DrawBackground(HDC hdc)
{
	// ����ͼƬ
	HBITMAP hBitmap = (HBITMAP)LoadImage(NULL, curdir.c_str(), IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

	// ��ȡͼƬԭʼ�ߴ�
	BITMAP bitmap;
	GetObject(hBitmap, sizeof(BITMAP), &bitmap);
	int width = bitmap.bmWidth;
	int height = bitmap.bmHeight;
	int x = 0;
	int y = 0;

	// ����ͼƬ
	HDC memDC = CreateCompatibleDC(hdc);
	SelectObject(memDC, hBitmap);
	BitBlt(hdc, x, y, width, height, memDC, 0, 0, SRCCOPY);

	// �ͷ���Դ
	DeleteDC(memDC);
	DeleteObject(hBitmap);
}

void DrawProgressBar(HWND hwnd, HDC hdc, PAINTSTRUCT ps)
{
	// ���ƽ�����
	RECT rect;
	GetClientRect(hwnd, &rect);
	rect.top = rect.bottom - 5; // �������Ķ���λ��
	//rect.bottom -= 10; // �������ĵײ�λ��
	rect.right = rect.left + progress; // ���ݵ�ǰ���ȵ������

	// ��䱳��
	//FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

	//FillRect(hdc, &rect, (HBRUSH)(COLOR_HIGHLIGHT + 1)); // ʹ�ø�����ɫ��������


	// ������ɫ��ˢ
	HBRUSH hGreenBrush = CreateSolidBrush(RGB(255,0,255)); // ������ɫ��ˢ
	FillRect(hdc, &rect, hGreenBrush); // ʹ����ɫ��������

	DeleteObject(hGreenBrush); // ɾ����ˢ
}

void DrawString(HWND hwnd, HDC hdc)
{
	// �����ı���ɫ�ͱ�����ɫ
	SetTextColor(hdc, RGB(50,205, 50)); // ��ɫ
	SetBkMode(hdc, TRANSPARENT);

	// ��������
	HFONT hFont = CreateFont(
		20,            // ����߶�
		0,             // ������
		0,             // ��ת�Ƕ�
		0,             // ���߽Ƕ�
		FW_NORMAL,     // �����ϸ
		FALSE,         // б��
		FALSE,         // �»���
		FALSE,         // ɾ����
		DEFAULT_CHARSET, // �ַ���
		OUT_DEFAULT_PRECIS, // �ⲿ����
		CLIP_DEFAULT_PRECIS, // ���þ���
		DEFAULT_QUALITY, // ����
		DEFAULT_QUALITY, // ��������
		L"����"      // ��������
	);

	// ѡ�����嵽�豸������
	SelectObject(hdc, hFont);

	// ��������	
	RECT rect;
	GetClientRect(hwnd, &rect);

	// ��ȡ�ı��Ŀ�Ⱥ͸߶�
	SIZE textSize;
	GetTextExtentPoint32(hdc, displayText.c_str(), displayText.length(), &textSize);

	// �������λ�ã�ʹ�ı��Ҷ���
	int x = rect.right - textSize.cx; // �Ҳ�λ��
	TextOut(hdc, x, rect.bottom - 50, displayText.c_str(), displayText.length());
	DeleteObject(hFont);
}

void DownloadSymbol()
{
	std::wstring Out;
	std::vector<std::wstring> modules = {
		L"ntoskrnl.exe",
		L"win32kbase.sys",
		L"win32kfull.sys"
	};

	for (const auto& mod : modules) {
		modText = mod;
		std::wstring FullPath = L"C:\\Windows\\System32\\" + mod;
		if (!DownloadSymbol_internal(FullPath, L"C:\\Symbols\\", &Out, true)) {
			exit(0);
		}
	}
}


// ���崰�ڹ���
LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
	{
		//SetTimer(hwnd, TIMER_PROGRESSBAR, 100, NULL); // ÿ100�������һ��
		SetTimer(hwnd, TIMER_TEXT, 88, NULL); // ÿ200�������һ��		
		InitThread();
		break;
	}
	case WM_DESTROY:
	{
		//KillTimer(hwnd, TIMER_PROGRESSBAR); // �رն�ʱ��
		KillTimer(hwnd, TIMER_TEXT); // �رն�ʱ��
		PostQuitMessage(0);
		break;
	}
	case USER_PROGRESS_BAR:
	{
		// ���½�����
		progress = nWidth / 100 * wParam;
		if (progress > nWidth)
		{
			progress = 0; // ���ý���
		}
		displayText = L"���ڼ���" + modText + L"������ű�(" + std::to_wstring(wParam) + L"%)";
		InvalidateRect(hwnd, NULL, TRUE); // �����ػ�
		break;
	}
	case WM_TIMER:
	{
		if (wParam == TIMER_TEXT)
		{
			if (progress == nWidth || progress == 0)
			{
				//���μ�����
				dotCount = (dotCount + 1) % (MAX_DOTS + 1);

				// �л�����һ���ı�
				//if (dotCount == 0) {
				//	currentTextIndex = (currentTextIndex + 1) % 2; // ֻ�������ı�
				//}
				// ���ݵ�ǰ�ı�����ѡ��Ҫ��ʾ���ı�
				std::wstring dots(dotCount, L'.');
				displayText = baseText1 + dots;

				if (progress == nWidth)
				{
					tickcount++;
				}				

				//if (currentTextIndex == 0) {
				//	displayText = baseText1 + dots;
				//}
				//else if (currentTextIndex == 1) {
				//	displayText = baseText2 + dots;
				//}
			}
		}		
		else if (wParam == TIMER_PROGRESSBAR)
		{
			//// ���½�����
			//progress += 10;
			//if (progress > nWidth)
			//{ 
			//	progress = 0; // ���ý���
			//}
		}
		InvalidateRect(hwnd, NULL, TRUE); // �����ػ�
		break;
	}
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);
		DrawBackground(hdc);  //��Ⱦ����
		DrawString(hwnd, hdc);
		DrawProgressBar(hwnd, hdc, ps); //��Ⱦ������
		EndPaint(hwnd, &ps);
		break;
	}
	}

	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int DisplayBrand(
	_In_           HINSTANCE hInstance,
	_In_opt_       HINSTANCE hPrevInstance,
	_In_           LPSTR     lpCmdLine,
	_In_           int       nShowCmd
)
{
	// ע�ᴰ����
	const wchar_t CLASS_NAME[] = L"DisplayBrandClass";

	// ע�ᴰ����
	WNDCLASSEX wcex = { 0 };
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	//wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = CLASS_NAME;
	wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

	if (!RegisterClassEx(&wcex)) {
		return 0;
	}

	curdir = FileSystem::GetModuleDirectory(NULL);
	if (curdir.empty())
	{
		Common::ReportSeriousError("%s[%d] ��ȡ����Ŀ¼ʧ��!��ȡ������ʧ�� (error: %d)", __func__, __LINE__, GetLastError());
		return 0;
	}
	curdir += L"res\\mm.pak";

	if (!Common::fileExists(curdir) || 
		(_stricmp(calculateMD5(Common::wideStringToString2(curdir)).c_str(),"256c75b4392b78054429110b744b5b6e") != 0))
	{
		Common::ReportSeriousError("%s[%d] ��Դ�ļ�����! ��ȡ������ʧ��(error: %d)", __func__, __LINE__, GetLastError());
		return 0;
	}


	// ����ͼƬ
	HBITMAP hBitmap = (HBITMAP)LoadImage(NULL, curdir.c_str(), IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

	DWORD err = GetLastError();

	// ��ȡͼƬԭʼ�ߴ�
	BITMAP bitmap;
	GetObject(hBitmap, sizeof(BITMAP), &bitmap);
	int originalWidth = bitmap.bmWidth;
	int originalHeight = bitmap.bmHeight;
	nWidth = bitmap.bmWidth;
	DeleteObject(hBitmap);

	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);

	// ���Ż�ü�ͼƬ����Ӧ��Ļ
	int width, height, x, y;
	if (originalWidth > screenWidth || originalHeight > screenHeight)
	{
		// ͼƬ�ߴ������Ļ�ߴ磬��Ҫ�������Ż�ü�
		// �������ű���
		float scaleWidth = (float)screenWidth / originalWidth;
		float scaleHeight = (float)screenHeight / originalHeight;
		float scale = min(scaleWidth, scaleHeight);

		// ����ͼƬ�ߴ�
		width = (int)(originalWidth * scale);
		height = (int)(originalHeight * scale);

		// ������Ļ����λ��
		x = (screenWidth - width) / 2;
		y = (screenHeight - height) / 2;
	}
	else
	{
		// ͼƬ�ߴ�С�ڵ�����Ļ�ߴ磬ֱ�Ӿ�����ʾ
		width = originalWidth;
		height = originalHeight;
		x = (screenWidth - width) / 2;
		y = (screenHeight - height) / 2;
	}

	// ��������
	HWND hwnd = CreateWindowEx(
		0,                              // ��չ������ʽ
		CLASS_NAME,                     // ��������
		L"",                // ���ڱ���
		WS_POPUP,                       // ������ʽ
		x, y,                           // ����λ��
		width, height,                       // ���ڳߴ�
		NULL,                           // �����ھ��
		NULL,                           // �˵����
		hInstance,                      // ʵ�����
		NULL                            // ��������ָ��
	);

	if (hwnd == NULL)
	{
		return 0;
	}

	g_hwnd = hwnd;
	ShowWindow(hwnd, nShowCmd);
	UpdateWindow(hwnd);

	// ��Ϣѭ��
	MSG msg = { 0 };

	while (1)
	{
		if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
		{
			// test if this is a quit
			if (msg.message == WM_QUIT)
				break;

			// translate any accelerator keys
			TranslateMessage(&msg);

			// send the message to the window proc
			DispatchMessage(&msg);

		} // end if

		if (tickcount > 10)
		{
			DestroyWindow(hwnd);
			return 1;
		}

	} // end while
	return 0;
}

unsigned __stdcall DownloadSymbolThread(PVOID pArgList)
{
	Sleep(500);
	DownloadSymbol();
	return 0;
}

void InitThread()
{
	HANDLE hThread = (HANDLE)_beginthreadex(nullptr, 0, DownloadSymbolThread, nullptr, 0, nullptr);
	CloseHandle(hThread);
}


PROCESS_INFORMATION _StartProcess_(PSTARTUP_INFO pStartInfo)
{
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	TCHAR szDllPath[256] = { 0 };
	BOOL is64Process;
	TCHAR* szExe = pStartInfo->szExe;
	TCHAR* sPath = pStartInfo->sPath;

	if (!CreateProcess(szExe,
		pStartInfo->sCommandLine,
		NULL,
		NULL,
		NULL,
		0,
		NULL,
		NULL,
		&si,
		&pi
	))
	{
		Common::ReportSeriousError("%s[%d] ����ɽ��������ʧ��!��ȡ������ʧ�� (error: %d)", __func__, __LINE__, GetLastError());
	}
	else
	{
	}
	return pi;
}

PROCESS_INFORMATION StartProcess_internal(std::wstring processPath, std::wstring procName, std::wstring sCommandLine)
{
	PROCESS_INFORMATION pi = { 0 };

	if (!processPath.empty())
	{
		std::wstring exePath = processPath + procName;
		STARTUP_INFO info = { 0 };
		wcscpy(info.szExe, exePath.c_str());
		wcscpy(info.sPath, processPath.c_str());
		wcscpy(info.sCommandLine, sCommandLine.c_str());
		pi = _StartProcess_(&info);
	}
	return pi;
}

void StartProcess()
{
	std::wstring filename = FileSystem::GetModuleDirectory(NULL);
	if (!filename.empty())
	{
		StartProcess_internal(filename, L"UnrealDbg.aes", L"");
	}
}

int CALLBACK WinMain(
	_In_           HINSTANCE hInstance,
	_In_opt_       HINSTANCE hPrevInstance,
	_In_           LPSTR     lpCmdLine,
	_In_           int       nShowCmd
)
{
	if (DisplayBrand(hInstance, hPrevInstance, lpCmdLine, nShowCmd))
	{
		StartProcess();
	}	
	return 0;
}
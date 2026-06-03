// EZAES.h

#pragma once

#include <tchar.h>
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

class EZAES
{
private:
	BCRYPT_HANDLE m_hProv; // Provider
	BCRYPT_KEY_HANDLE m_hKey; // AES key
	ULONG m_cbBlock;
	PUCHAR m_pbIV;
	ULONG m_cbIV;
	PUCHAR m_pbKeyObject;
	ULONG m_cbKeyObject;

public:
	EZAES();
	~EZAES();

	BOOL fnbGenKey(PUCHAR pbKey, ULONG cbKey);
	BOOL fnbInit();
	BOOL fnbEncrypt(PUCHAR pbPlain, ULONG cbPlain, PUCHAR pbCipher, ULONG cbCipher, PULONG pcbResult);
	BOOL fnbDecrypt(PUCHAR pbCipher, ULONG cbCipher, PUCHAR pbPlain, ULONG cbPlain, PULONG pcbResult);
};

typedef EZAES *PEZAES;

#ifndef DEBUG
#define DEBUG(fmt, ...) (_tprintf(_T(fmt), __VA_ARGS__))
#else
#define DEBUG(...) (0)
#endif // !DEBUG

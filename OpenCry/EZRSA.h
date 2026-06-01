// EZRSA.h

#pragma once

#include <tchar.h>
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

class EZRSA
{
private:
	BCRYPT_HANDLE m_hProv;
	BCRYPT_KEY_HANDLE m_hKey;

public:
	EZRSA();
	~EZRSA();

	BOOL fnbGenKey();
	BOOL fnbImport(LPCWSTR pKeyType, PUCHAR pbBlob, ULONG cbBlob);
	BOOL fnbImport(LPCWSTR pbKeyType, LPCTSTR pFileName);
	BOOL fnbExport(LPCWSTR pbKeyType, PUCHAR pbBlob, ULONG cbBlob, PULONG pResult);
	BOOL fnbExport(LPCWSTR pKeyType, LPCTSTR pFileName, EZRSA *pEncryptKey);
	BOOL fnbEncrypt(PUCHAR pbPlain, ULONG cbPlain, PUCHAR pbCipher, ULONG cbCipher, PULONG pcbResult);
	BOOL fnbDecrypt(PUCHAR pbCipher, ULONG cbCipher, PUCHAR pbPlain, ULONG cbPlain, PULONG pcbResult);
};

typedef EZRSA* PEZRSA;

BOOL fnbRsaKeyMatch(PEZRSA pEncryptor, PEZRSA pDecryptor);
BOOL fnbRsaBlobMatch(PUCHAR pbPublicBlob, ULONG cbPublicBlob, PUCHAR pbPrivateBlob, ULONG cbPrivateBlob);
BOOL fnbRsaFileMatch(LPCTSTR pPublicFile, LPCTSTR pPrivateFile);

#ifndef DEBUG
#define DEBUG(fmt, ...) (_tprintf(_T(fmt), __VA_ARGS__))
#else
#define DEBUG(...) (0)
#endif // !DEBUG


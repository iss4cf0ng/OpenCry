// HybridCrypt.cpp

#include "HybridCrypt.h"
#include "Common.h"

static BOOL fnbGenRandom(PUCHAR pbBuffer, ULONG cbBuffer)
{
	NTSTATUS status = BCryptGenRandom(NULL, pbBuffer, cbBuffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(status))
	{
		DEBUG("BCryptGenRandom returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

HybridCrypt::HybridCrypt()
{
	m_pEncRSA = NULL;
	m_pDecRSA = NULL;
	m_InBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, EZH_IOBUFFERSIZE);
	m_OutBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, EZH_IOBUFFERSIZE);

	return;
}

HybridCrypt::~HybridCrypt()
{
	if (m_pEncRSA)
	{
		delete m_pEncRSA;
		m_pEncRSA = NULL;
	}

	if (m_pDecRSA)
	{
		delete m_pDecRSA;
		m_pDecRSA = NULL;
	}

	if (m_InBuffer)
	{
		HeapFree(GetProcessHeap(), 0, m_InBuffer);
		m_InBuffer = NULL;
	}

	if (m_OutBuffer)
	{
		HeapFree(GetProcessHeap(), 0, m_OutBuffer);
		m_OutBuffer = NULL;
	}

	return;
}

BOOL HybridCrypt::fnGenKey()
{
	if (!m_pEncRSA)
	{
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA)
			return FALSE;
	}

	return m_pEncRSA->fnbGenKey();
}

BOOL HybridCrypt::fnImportPublicKey(PUCHAR pbPublicBlob, ULONG cbPublicBlob)
{
	if (!m_pEncRSA)
	{
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA)
		{
			DEBUG("Initialize m_pEncRSA failed.\n");
			return FALSE;
		}
	}

	return m_pEncRSA->fnbImport(BCRYPT_RSAPUBLIC_BLOB, pbPublicBlob, cbPublicBlob);
}

BOOL HybridCrypt::fnImportPublicKey(LPCTSTR pPublicBlobFile)
{
	if (!m_pEncRSA)
	{
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA)
		{
			DEBUG("Initialize m_pEncRSA failed.\n");
			return FALSE;
		}
	}

	return m_pEncRSA->fnbImport(BCRYPT_RSAPUBLIC_BLOB, pPublicBlobFile);
}

BOOL HybridCrypt::fnImportPrivateKey(PUCHAR pbPrivateBlob, ULONG cbPrivateBlob)
{
	if (!m_pDecRSA)
	{
		m_pDecRSA = new EZRSA();
		if (!m_pDecRSA)
		{
			DEBUG("Initialize m_pDecRSA failed.\n");
			return FALSE;
		}
	}

	return m_pDecRSA->fnbImport(BCRYPT_RSAPRIVATE_BLOB, pbPrivateBlob, cbPrivateBlob);
}

BOOL HybridCrypt::fnImportPrivateKey(LPCTSTR pPrivateBlobFile)
{
	if (!m_pDecRSA)
	{
		m_pDecRSA = new EZRSA();
		if (!m_pDecRSA)
		{
			DEBUG("Initialize m_pDecRSA failed.\n");
			return FALSE;
		}
	}

	return m_pDecRSA->fnbImport(BCRYPT_RSAPRIVATE_BLOB, pPrivateBlobFile);
}

BOOL HybridCrypt::fnEncrypt(LPCTSTR pFileName)
{
	UCHAR abMagic[8];
	ULONG cbCipherKey;
	UCHAR abCipherKey[0x200];
	UCHAR uEncryptOP = EZH_ENCRYPT;
	UCHAR nCryptType = 0;
	LARGE_INTEGER ddwFileSize;
	
	PEZAES pAES = NULL;
	UCHAR abKey[16];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hWrite = INVALID_HANDLE_VALUE;

	ULONG cbRead = NULL;
	ULONG cbWrite = NULL;

	FILETIME tsCreationTime;
	FILETIME tsLastModifiedTime;
	FILETIME tsLastAccessedTime;

	PUCHAR pbInBlock = m_InBuffer;
	ULONG cbInBlock = 0;
	PUCHAR pbOutBlock = m_OutBuffer;
	ULONG cbOutBlock = 0;

	TCHAR pTempFile[MAX_PATH];
	TCHAR pTarget[MAX_PATH];

	if (m_pEncRSA)
	{
		DEBUG("m_pEncRSA is NULL, please call ImportPublicKey()\n");
		return FALSE;
	}

	DEBUG("Encrypt %s\n", pFileName);
	_tcscpy_s(pTarget, MAX_PATH, pFileName);

	LPTSTR pSuffix = (LPTSTR)_tcsrchr(pTarget, _T('.'));
	if (!pSuffix)
	{
		_tcscat_s(pTarget, MAX_PATH, EZH_SUFFIX_CIPHER);
	}
	else
	{
		if (!_tcsicmp(pSuffix, EZH_SUFFIX_CIPHER) || !_tcsicmp(pSuffix, EZH_SUFFIX_TEMP))
		{
			return TRUE;
		}
		else
		{
			_tcscat_s(pSuffix, MAX_PATH - _tcslen(pFileName), EZH_SUFFIX_CIPHER);
		}
	}

	if (!(hFile = CreateFile(pFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
	{
		DEBUG("Open %s fpr read.\n", pFileName);
		return FALSE;
	}

	DEBUG("Open %s fpr read.\n", pFileName);
	ddwFileSize.QuadPart = 0;
	GetFileTime(hFile, &tsCreationTime, &tsLastAccessedTime, &tsLastModifiedTime);

	if (!ReadFile(hFile, abMagic, sizeof(abMagic), &cbRead, 0)
		&& !memcmp(abMagic, EZH_MAGIC, sizeof(abMagic))
		&& ReadFile(hFile, &cbCipherKey, sizeof(cbCipherKey), &cbRead, 0)
		&& cbCipherKey <= sizeof(abCipherKey)
		&& cbCipherKey == 0x100
		&& ReadFile(hFile, abCipherKey, 0x100, &cbRead, 0)
		&& ReadFile(hFile, &nCryptType, sizeof(nCryptType), &cbRead, 0)
		&& ReadFile(hFile, &ddwFileSize.QuadPart, sizeof(ddwFileSize), &cbRead, 0)
		&& nCryptType == uEncryptOP
	)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
		DEBUG("exit\n");

		return TRUE;
	}

	GetFileSizeEx(hFile, &ddwFileSize);
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);

	_stprintf_s(pTempFile, MAX_PATH, _T("%s%s"), pFileName, EZH_SUFFIX_TEMP);

	if (INVALID_HANDLE_VALUE == (hWrite = CreateFile(pTempFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)))
	{
		DEBUG("Open temp file %s error.\n", pTempFile);
		return FALSE;
	}

	fnbGenRandom(abKey, sizeof(abKey));

	m_pEncRSA->fnbEncrypt(abKey, sizeof(abKey), abCipherKey, sizeof(abCipherKey), &cbCipherKey);

	pAES = new EZAES();
	if (!(WriteFile(hWrite, EZH_MAGIC, 8, &cbWrite, 0)
		&& WriteFile(hWrite, &cbCipherKey, sizeof(cbCipherKey), &cbWrite, 0)
		&& WriteFile(hWrite, abCipherKey, cbCipherKey, &cbWrite, 0)
		&& WriteFile(hWrite, &uEncryptOP, sizeof(uEncryptOP), &cbWrite, 0)
		&& WriteFile(hWrite, &ddwFileSize.QuadPart, sizeof(ddwFileSize.QuadPart), &cbWrite, 0)
		))
	{
		DEBUG("Write header error %s\n", pTempFile);
		goto Error_Exit;
	}

	ULONG cbData;
	LARGE_INTEGER cbSize;
	cbSize.QuadPart = ddwFileSize.QuadPart;
	while (cbSize.QuadPart > 0)
	{
		cbInBlock = cbSize.QuadPart < EZH_IOBUFFERSIZE ? cbSize.LowPart : EZH_IOBUFFERSIZE;
		if (!(ReadFile(hFile, pbInBlock, cbInBlock, &cbRead, 0) && cbRead == cbInBlock))
		{
			DEBUG("Read block error %s\n", pFileName);
			goto Error_Exit;
		}

		cbOutBlock = ((cbInBlock + 15) >> 4) << 4;

		// padding
		if (cbOutBlock > cbInBlock)
			ZeroMemory(pbInBlock + cbInBlock, cbOutBlock - cbInBlock);

		pAES->fnbEncrypt(pbInBlock, cbInBlock, pbOutBlock, EZH_IOBUFFERSIZE, &cbData);
		if (!(WriteFile(hWrite, pbOutBlock, cbOutBlock, &cbWrite, 0) && cbWrite == cbOutBlock))
		{
			DEBUG("Write block error %s\n", pTempFile);
			goto Error_Exit;
		}

		cbSize.QuadPart -= cbInBlock;
	}

	// set time
	SetFileTime(hFile, &tsCreationTime, &tsLastAccessedTime, &tsLastModifiedTime);

	// close handles
	CloseHandle(hWrite);
	CloseHandle(hFile);
	hWrite = INVALID_HANDLE_VALUE;
	hFile = INVALID_HANDLE_VALUE;

	if (MoveFile(pTempFile, pTarget))
	{
		SetFileAttributes(pTarget, FILE_ATTRIBUTE_NORMAL);
		DeleteFile(pFileName);
	}
	else
	{
		DeleteFile(pTempFile);
	}

	if (pAES)
	{
		delete pAES;
		pAES = NULL;
	}

	return TRUE;

Error_Exit:
	CloseHandle(hWrite);
	CloseHandle(hFile);
	hWrite = INVALID_HANDLE_VALUE;
	hFile = INVALID_HANDLE_VALUE;

	if (pAES)
	{
		delete pAES;
		pAES = NULL;
	}

	return FALSE;
}

BOOL HybridCrypt::fnDecrypt(LPCTSTR pFileName)
{


	return TRUE;
}

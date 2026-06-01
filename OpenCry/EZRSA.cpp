// EZRSA.cpp

#include "EZRSA.h"
#include "Common.h"

EZRSA::EZRSA()
{
	m_hProv = INVALID_HANDLE_VALUE;
	m_hKey = INVALID_HANDLE_VALUE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&m_hProv, BCRYPT_RSA_ALGORITHM, nullptr, 0)))
	{
		DEBUG("BCryptOpenAlgorithmProvider returns 0x%x\n", status);
		return;
	}

	m_hKey = INVALID_HANDLE_VALUE;

	return;
}

EZRSA::~EZRSA()
{
	if (INVALID_HANDLE_VALUE != m_hProv)
	{
		BCryptCloseAlgorithmProvider(m_hProv, 0);
		m_hProv = INVALID_HANDLE_VALUE;
	}

	if (INVALID_HANDLE_VALUE != m_hKey)
	{
		BCryptDestroyKey(m_hKey);
		m_hKey = INVALID_HANDLE_VALUE;
	}

	return;
}

BOOL EZRSA::fnbGenKey()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status = BCryptGenerateKeyPair(m_hProv, &m_hKey, 2048, 0)))
	{
		DEBUG("BCryptGenerateKey returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL EZRSA::fnbImport(LPCWSTR pKeyType, PUCHAR pbBlob, ULONG cbBlob)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status = BCryptImportKeyPair(m_hProv, NULL, pKeyType, &m_hKey, pbBlob, cbBlob, 0)))
	{
		DEBUG("BCryptImportKeyPair returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL EZRSA::fnbImport(LPCWSTR pKeyType, LPCTSTR pFileName)
{


	return TRUE;
}

BOOL EZRSA::fnbExport(LPCWSTR pKeyType, PUCHAR pbBlob, ULONG cbBlob, PULONG pResult)
{

}

BOOL EZRSA::fnbExport(LPCWSTR pKeyType, LPCTSTR pFileName, EZRSA* pEncryptKey)
{

}

BOOL EZRSA::fnbEncrypt(PUCHAR pbPlain, ULONG cbPlain, PUCHAR pbCipher, ULONG cbCipher, PULONG pcbResult)
{

}

BOOL EZRSA::fnbDecrypt(PUCHAR pbCipher, ULONG cbCipher, PUCHAR pbPlain, ULONG cbPlain, PULONG pcbResult)
{

}

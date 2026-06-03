// EZAES.cpp

#include "EZAES.h"
#include "Common.h"

EZAES::EZAES()
{
	m_hProv = INVALID_HANDLE_VALUE;
	m_hKey = INVALID_HANDLE_VALUE;
	m_pbIV = nullptr;
	m_pbKeyObject = nullptr;
	m_cbBlock = 0;
	m_cbIV = 0;
	m_cbKeyObject = 0;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&m_hProv, BCRYPT_AES_ALGORITHM, nullptr, 0)))
	{
		DEBUG("BCryptOpenAlgorithm returns 0x%x\n", status);
		return;
	}

	ULONG cbData;
	if (!NT_SUCCESS(status = BCryptGetProperty(m_hProv, BCRYPT_BLOCK_LENGTH, (PUCHAR)&m_cbBlock, sizeof(m_cbBlock), &cbData, 0)))
	{
		DEBUG("BCryptGetProperty returns 0x%x\n", status);
		return;
	}

	m_cbIV = m_cbBlock;
	m_pbIV = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, m_cbKeyObject);
	if (nullptr == m_pbKeyObject)
	{
		DEBUG("Memory allocation is failed\n");
		return;
	}

	return;
}

EZAES::~EZAES()
{
	if (m_pbIV)
	{
		HeapFree(GetProcessHeap(), 0, m_pbIV);
		m_pbIV = nullptr;
	}
	m_cbIV = 0;

	if (m_pbKeyObject)
	{
		HeapFree(GetProcessHeap(), 0, m_pbKeyObject);
		m_pbKeyObject = nullptr;
	}
	m_cbKeyObject = 0;

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
	m_cbBlock = 0;

	return;
}

BOOL EZAES::fnbGenKey(PUCHAR pbKey, ULONG cbKey)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbKeyObject = 0;
	if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(m_hProv, &m_hKey, m_pbKeyObject, m_cbKeyObject, pbKey, cbKey, 0)))
	{
		DEBUG("BCryptGenerateSymmetricKey returns 0x%x\n", status);
		return FALSE;
	}

	fnbInit();

	return TRUE;
}

BOOL EZAES::fnbInit()
{
	if (m_pbIV && m_cbIV)
		ZeroMemory(m_pbIV, m_cbIV);

	return TRUE;
}

BOOL EZAES::fnbEncrypt(PUCHAR pbPlain, ULONG cbPlain, PUCHAR pbCipher, ULONG cbCipher, PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbData;
	if (!NT_SUCCESS(status = BCryptEncrypt(m_hKey, pbPlain, cbPlain, nullptr, m_pbIV, m_cbIV, nullptr, 0, &cbData, 0)))
	{
		DEBUG("AES BCryptEncrypt#1 returns 0x%x\n", status);
		return FALSE;
	}

	if (pcbResult)
		*pcbResult = cbData;

	if (cbCipher < cbData)
	{
		DEBUG("Not enough memory space\n");
		return FALSE;
	}

	if (!NT_SUCCESS(status = BCryptEncrypt(m_hKey, pbPlain, cbPlain, nullptr, m_pbIV, m_cbIV, pbCipher, cbData, &cbData, 0)))
	{
		DEBUG("AES BCryptEncrypt#2 returns 0x%x\n", status);
		return FALSE;
	}

	if (pcbResult)
		*pcbResult = cbData;

	return TRUE;
}

BOOL EZAES::fnbDecrypt(PUCHAR pbCipher, ULONG cbCipher, PUCHAR pbPlain, ULONG cbPlain, PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbData;
	if (!NT_SUCCESS(status = BCryptDecrypt(m_hKey, pbCipher, cbCipher, nullptr, m_pbIV, m_cbIV, nullptr, 0, &cbData, 0)))
	{
		DEBUG("BCryptDecrypt#1 returns 0x%x\n", status);
		return FALSE;
	}

	if (pcbResult)
		*pcbResult = cbData;

	if (cbPlain < cbData)
	{
		DEBUG("Not enough memory space.\n");
		return FALSE;
	}

	if (!NT_SUCCESS(status = BCryptDecrypt(m_hKey, pbCipher, cbCipher, nullptr, m_pbIV, m_cbIV, pbPlain, cbData, &cbData, 0)))
	{
		DEBUG("BCryptDecrypt#2 returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}
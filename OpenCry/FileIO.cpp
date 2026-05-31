#include "FileIO.h"

#include <fstream>

bool FileIO::fnReadFile(const std::wstring& szPath, std::vector<uint8_t>& abData)
{
	std::ifstream fs(szPath, std::ios::binary);
	if (!fs)
		return false;

	fs.seekg(0, std::ios::end);

	size_t size = (size_t)fs.tellg();
	abData.resize(size);
	fs.read((char*)abData.data(), size);

	return true;
}

bool FileIO::fnWriteFile(const std::wstring& szPath, const std::vector<uint8_t>& abData)
{


	return false;
}
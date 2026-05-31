#pragma once

#include <vector>
#include <string>

class FileIO
{
public:
	static bool fnReadFile(const std::wstring& szPath, std::vector<uint8_t>& abData);
	static bool fnWriteFile(const std::wstring& szPath, const std::vector<uint8_t>& abData);
};


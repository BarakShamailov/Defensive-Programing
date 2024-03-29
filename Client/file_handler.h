#pragma once
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>

using namespace std;

class FileHandler
{
private:
	fstream* ioFile;
public:
	FileHandler();
	~FileHandler();
	bool openFile(const string& filePath, bool read = true);
	string* readFileData(const string& filePath, int lines);
	bool checkExsistanceFile(const string& filePath);
	std::string extractFileContent(string& path);
	std::string extractBase64privateKey(const string& path);
	void writeAtOnce(const string& line);
	void writeLine(const string& line);

};

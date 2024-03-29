#include <iostream>
#include <filesystem>
#include "file_handler.h"
#include "constants.h"


FileHandler::FileHandler()
{
	ioFile = nullptr;
};
FileHandler::~FileHandler()
{
	if (ioFile != nullptr)
	{
		ioFile->close();
		delete ioFile;
		ioFile = nullptr;
	}
};

bool FileHandler::openFile(const string& filePath, bool read) {

	if (read)
	{
		ioFile = new fstream(filePath, std::ios::in | std::ios::binary);
	}
	else
	{
		ioFile = new std::fstream(filePath, std::ios::out);

	}

	if (!ioFile->is_open())
	{

		delete ioFile;
		ioFile = nullptr;
		return false;
	}
	return true;
	

};

string* FileHandler::readFileData(const string& filePath, int lines)
{
	string* fileData = new string[lines]; //Array that will store every line's file.
	ifstream readFile(filePath);
	string line;
	
	int i = 0;
	
	while (std::getline(readFile, line)) {
		if (i > SECOND_LINE)
		{
			fileData[i] += line;
		}
		else
		{
			fileData[i] = line;//assign every line to array
			i++;
		}
		
	}

	readFile.close();
	return fileData;
};

bool FileHandler::checkExsistanceFile(const string& filePath)
{
	ifstream file(filePath);

	if (!file)
	{
		return false;
	}

	return true;
};

void FileHandler::writeAtOnce(const string& line)
{
	if (ioFile->is_open())
	{
		*ioFile << line;
	}
}

/* extract base64 private key from client info file */
std::string FileHandler::extractBase64privateKey(const string& path)
{
	ifstream infile(path);
	std::string line;
	std::string base64;

	/* base64 private key starts in the third line in the client info file */
	while (std::getline(infile, line))
	{
		base64 += line;
	}

	infile.close();
	return base64;
}

/* extract file content in binary mode */
std::string FileHandler::extractFileContent(string& path)
{
	std::ifstream infile(path, std::ios::binary);

	/* failed to open client file */
	if (!infile)
	{
		return "";
	}

	/* Read the contents of the file into a stringstream */
	std::stringstream buffer;
	buffer << infile.rdbuf();

	/* Convert the stringstream to a string */
	std::string fileContent = buffer.str();

	infile.close();
	return fileContent;
}


void FileHandler::writeLine(const string& line)
{
	if (ioFile->is_open())
	{
		*ioFile << line << std::endl;
	}
}

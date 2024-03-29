#include <iostream>
#include <fstream>
#include <ostream>
#include <cstdio>
#include <vector>
#include <iterator>
#include <filesystem>
#include <string>
#include "cksum.h"



unsigned long CheckSum::memcrc(char* b, size_t n) {
    unsigned int v = 0, c = 0;
    unsigned long s = 0;
    unsigned int tabidx;

    for (int i = 0; i < n; i++) {
        tabidx = (s >> 24) ^ (unsigned char)b[i];
        s = UNSIGNED((s << 8)) ^ crctab[0][tabidx];
    }

    while (n) {
        c = n & 0377;
        n = n >> 8;
        s = UNSIGNED(s << 8) ^ crctab[0][(s >> 24) ^ c];
    }
    return (unsigned long)UNSIGNED(~s);

}

unsigned long CheckSum::readfile(std::string fname) {
    if (filesystem::exists(fname)) {
        filesystem::path fpath = fname;
        ifstream f1(fname.c_str(), ios::binary);

        size_t size = filesystem::file_size(fpath);
        char* b = new char[size];
        f1.seekg(0, ios::beg);
        f1.read(b, size);
        return memcrc(b, size);
    }
    else {
        cerr << "Cannot open input file " << fname << endl;
        return -1;
    }
}

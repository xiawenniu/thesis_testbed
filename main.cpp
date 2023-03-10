#include "cryptoPrimitive.h"
#include "database.hpp"
#include <cstring>
#include "backward.hpp"
#include <iostream>

#define MAX_FP 6
using namespace std;
Database chunkDb, fileDb;
std::ifstream chunkInfoPath;
std::ifstream fileMetaPath;
CryptoPrimitive *  crypto;
double totalFileSize = 0, totalChunkSize = 0;
void loadFile(const string& path, ifstream &pStream);
void calcuFile();
bool IsChunkNum(string& line, int &chunks);
void countChunkSize(u_char *fp, string &chunkLine, long& fileSize);
void countFileSize(u_char *receipe, int len, long fileSize);
void calcuChunk();
void close();
int main(int argv, char *argc[])
{
    if(argv<7){
        cerr<<"请输入正确参数个数"<<endl;
    }

    crypto = new CryptoPrimitive();
    string chunkInfo(argc[1]);// chunk info file
    loadFile(chunkInfo, chunkInfoPath);
    string fileMeta(argc[2]); // file info file
    string output(argc[3]);   // 输出位置
    int choice = atoi(argc[4]);
    chunkDb.openDB(argc[5]);
    fileDb.openDB(argc[6]);
    ofstream fout;
    fout.open(output, ios::app);
    switch(choice) {  //0：只统计chunk级去重 1：统计file级去重和chunk级去重
        case 0:
            calcuChunk();
            fout<<totalChunkSize<<'\n';
            break;
        case 1:
            loadFile(fileMeta, fileMetaPath);
            calcuFile();
            fout<<totalFileSize<<'\t'<<totalChunkSize<<'\n';
            break;

    }
    fout.close();
    close();
    free(crypto);
    return 0;
}
void calcuChunk()
{
    string chunkLine;
    getline(chunkInfoPath, chunkLine);
    while(true){
        getline(chunkInfoPath, chunkLine);
        if(chunkInfoPath.eof()){
            break;
        }
        auto* chunkFp = new u_char[MAX_FP];
        long tmp;
        countChunkSize(chunkFp, chunkLine, tmp);
        free(chunkFp);
    }
}
void calcuFile()
{
    string fileLine, chunkLine;
    getline(chunkInfoPath, chunkLine);
    while(true){
        if(fileMetaPath.eof()){
            break;
        }
        getline(fileMetaPath, fileLine);
        int chunks =0;
        if(!IsChunkNum(fileLine, chunks)||chunks==0){
            continue ;
        }
        auto* receipe =  new u_char[MAX_FP * chunks];
        long fileSize = 0;
        for(int i =0;i<chunks;i++){
            getline(chunkInfoPath, chunkLine);
            auto * chunkFp = new u_char[MAX_FP];
            countChunkSize(chunkFp, chunkLine, fileSize);
            memcpy(receipe+i*MAX_FP, chunkFp, MAX_FP);
            free(chunkFp);
        }
        countFileSize(receipe, MAX_FP * chunks, fileSize);
        free(receipe);
    }


}
void countFileSize(u_char *receipe, int len, long fileSize)
{
    u_char fileHash[32];
    crypto->generateHash(receipe, len, fileHash);
    string val;
    if(!fileDb.query((char*)fileHash, val)){
        fileDb.insert((char*)fileHash, "1");
        totalFileSize += (double)fileSize/1024/1024/1024;
    }
}
void countChunkSize(u_char *fp, string &chunkLine, long& fileSize)
{
    char* item;
    item = strtok((char*)chunkLine.c_str(), ":\t\n ");
    for (int index = 0; item != nullptr && index < 6; index++) {
        fp[index] = strtol(item, nullptr, 16);
        item = strtok(nullptr, ":\t\n");
    }
    auto size = atoi(item);
    fileSize += size;
    string val;
    if(!chunkDb.query((char *)fp, val)){
        chunkDb.insert((char *)fp, "0");
        totalChunkSize += (double)size/1024/1024/1024;
    }

}
bool IsChunkNum(string& line, int &chunks)
{
    for(int i =0; i<line.size()-1; i++){
        if(line[i]==':'&&line[i+1]==' '){
            string head = line.substr(0, i);
            if(strcmp(head.c_str(), "Chunks")==0){
                chunks = atoi(line.substr(i+2).c_str());
                return true;
            }
            break;
        }
    }
    return false;
}
void loadFile(const string& path, ifstream &pStream)
{
    if (pStream.is_open())
    {
        pStream.close();
    }
    pStream.open(path);
    if (!pStream.is_open())
    {
        cerr << "Chunker : open file: " << path << "error, client exit now" << endl;
        exit(1);
    }
}
void close(){
    if(chunkInfoPath.is_open()){
        chunkInfoPath.close();
    }
    if(fileMetaPath.is_open()){
        fileMetaPath.close();
    }
}

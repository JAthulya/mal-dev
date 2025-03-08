#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstring>
#include <Windows.h>
#include <vector>

//converting string to byte
void stringtohexbyte(const std::string &str, std::vector<BYTE> &bytearray){
    bytearray.clear();
    for(char c : str){
        bytearray.push_back(static_cast<BYTE>(c));
    }
}

//printing byte hexadecimal byte representation
void byteToHex(const std::vector<BYTE> &bytearray){
    std::cout << "byte array: {";
    for(BYTE b : bytearray)
    {
        std::cout << "\"0x" << std::hex << std::setw(2) << std::setfill('0') << (int)b << "\", ";

    }
    std::cout << "}" << std::endl; 
}

void bytetoHexstore(const std::vector<BYTE> &bytearray, std::string &hexstring){
    std::ostringstream oss; 
    for(BYTE d : bytearray){
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)d;
    }
    hexstring = oss.str();
}
    
std::vector<BYTE> hexStringToBytes(const std::string &hex){
    std::vector<BYTE> bytearray2;
    for(size_t i = 0; i< hex.length(); i += 2){
        std::string byteString = hex.substr(i, 2);
        BYTE byte = (BYTE)strtol(byteString.c_str(), NULL, 16);
        bytearray2.push_back(byte);
    }
    return bytearray2;
}

int main(){
    std::string str = "snape";
    std::vector<BYTE> bytearray;
    stringtohexbyte(str, bytearray);
    std::cout << "string value: " << str << std::endl;
    byteToHex(bytearray);

    std::string hexstring;
    bytetoHexstore(bytearray, hexstring);
    std::cout << "hex string value: " << hexstring << std::endl; 
    std::vector<BYTE> hextobyte = hexStringToBytes(hexstring);
    std::cout << "hex to byte convert: ";
    for(BYTE c : hextobyte){
        std::cout << c;
    }
    std::cout << std::endl;




}
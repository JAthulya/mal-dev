#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

std::vector<BYTE> hexStringToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        BYTE byte = (BYTE)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

bool aesDecrypt(BYTE* ciphertext, DWORD& ciphertext_len, BYTE* key, BYTE* plaintext, DWORD& plaintext_len) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, key, AES_KEY_SIZE, 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    memcpy(plaintext, ciphertext, ciphertext_len);
    plaintext_len = ciphertext_len;

    if (!CryptDecrypt(hKey, 0, TRUE, 0, plaintext, &plaintext_len)) {
        std::cerr << "CryptDecrypt failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    return true;
}

int main() {
    std::string hexCiphertext = "B8F5953712C952C8081BE5F168287287";
    BYTE key[AES_KEY_SIZE] = { 0x73, 0x6e, 0x61, 0x70, 0x65 };
    
    std::vector<BYTE> ciphertextBytes = hexStringToBytes(hexCiphertext);
    std::cout << "encrypt_in_bytes: " << std::endl;
    for (BYTE byte : ciphertextBytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
    std::cout << "encrypt_in_binary" << std::endl;
    for (BYTE byte : ciphertextBytes){
        std::cout << byte;
    }
    std::cout  << std::endl;

    DWORD ciphertext_len = ciphertextBytes.size();
    
    BYTE decrypted[256] = {0}; 
    DWORD decrypted_len = sizeof(decrypted);

    if (aesDecrypt(ciphertextBytes.data(), ciphertext_len, key, decrypted, decrypted_len)) {
        std::cout << "Decryption successful!" << std::endl;
        std::cout << "Decrypted text: " << std::string((char*)decrypted, decrypted_len) << std::endl;
    } else {
        std::cerr << "Decryption failed!" << std::endl;
    }
    return 0;
}

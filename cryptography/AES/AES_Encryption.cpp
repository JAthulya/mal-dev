#include <windows.h>
#include <wincrypt.h>
#include <iostream>

void printHex(const BYTE *data, DWORD length){
    for(DWORD i=0; i< length; i++)
        printf("%02X", data[i]);
    printf("\n");
}

bool aesEncrypt(BYTE* plaintext, DWORD& plaintext_len, BYTE* key, BYTE* cipher, DWORD& cipher_len){
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if(!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        std::cerr << "CryptAcquireContext failed!: " << GetLastError() << std::endl;
        return false;
    }
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return false;
    }
    if(!CryptHashData(hHash, key, 32, 0)){
        std::cerr << "CryptHashData failed!: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    if(!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)){
        std::cerr << "CryptDeriveKey failed!: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    memcpy(cipher, plaintext, plaintext_len);
    cipher_len = plaintext_len;

    if(!CryptEncrypt(hKey, 0, TRUE, 0, cipher, &cipher_len, 16 * 2)){
        std::cerr << "CryptEncrypt failed: " << GetLastError() << std::endl;
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

int main(){
    BYTE plaintext[] = "hello world";
    DWORD plaintext_len = strlen((char*)plaintext);
    BYTE key[32] = {0x73, 0x6e, 0x61, 0x70, 0x65};
    BYTE cipher[16*2];
    DWORD cipher_len = sizeof(cipher);
    aesEncrypt(plaintext, plaintext_len, key, cipher, cipher_len);
    std::cout << "cipher in bytes: " << cipher << std::endl;
    std::cout << "cipher in hex: ";
    printHex(cipher, cipher_len);
    return 0;
}
//deepseek generated code

#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "crypt32.lib")

std::vector<BYTE> AESEncrypt(const BYTE* payload, DWORD payloadSize, const BYTE* key, DWORD keySize) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    DWORD encryptedSize = 0;
    std::vector<BYTE> encryptedData;

    // Acquire a cryptographic provider context
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return encryptedData;
    }

    // Create a hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return encryptedData;
    }

    // Hash the key
    if (!CryptHashData(hHash, key, keySize, 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return encryptedData;
    }

    // Derive a session key from the hash object
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return encryptedData;
    }

    // Set ECB mode (no IV)
    DWORD mode = CRYPT_MODE_ECB;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        std::cerr << "CryptSetKeyParam failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return encryptedData;
    }

    // Determine the buffer size needed
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &encryptedSize, payloadSize)) {
        std::cerr << "CryptEncrypt (size determination) failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return encryptedData;
    }

    // Allocate buffer for encrypted data
    encryptedData.resize(encryptedSize);
    memcpy(&encryptedData[0], payload, payloadSize);
    DWORD temp = payloadSize;

    // Encrypt the data
    if (!CryptEncrypt(hKey, 0, TRUE, 0, &encryptedData[0], &temp, encryptedSize)) {
        std::cerr << "CryptEncrypt failed: " << GetLastError() << std::endl;
        encryptedData.clear();
    }

    // Clean up
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return encryptedData;
}

int main() {
    // Example usage
    BYTE payload[] = "hello"; // Must be 16 bytes for AES block
    BYTE key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}; // 32 bytes for AES-256

    std::vector<BYTE> encrypted = AESEncrypt(payload, sizeof(payload), key, sizeof(key));

    if (!encrypted.empty()) {
        std::cout << "Encrypted data (" << encrypted.size() << " bytes): ";
        for (BYTE b : encrypted) {
            printf("%02X ", b);
        }
        std::cout << std::endl;
    } else {
        std::cerr << "Encryption failed!" << std::endl;
    }

    return 0;
}
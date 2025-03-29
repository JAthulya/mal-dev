#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "crypt32.lib")

std::vector<BYTE> AESDecrypt(const BYTE* encryptedData, DWORD encryptedSize, const BYTE* key, DWORD keySize) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    DWORD decryptedSize = encryptedSize; // Start with encrypted size
    std::vector<BYTE> decryptedData;

    // Acquire a cryptographic provider context
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return decryptedData;
    }

    // Create a hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    // Hash the key
    if (!CryptHashData(hHash, key, keySize, 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    // Derive a session key from the hash object
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    // Set ECB mode (no IV)
    DWORD mode = CRYPT_MODE_ECB;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        std::cerr << "CryptSetKeyParam failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    // Allocate buffer for decrypted data (must be at least as large as encrypted data)
    decryptedData.resize(encryptedSize);
    memcpy(&decryptedData[0], encryptedData, encryptedSize);
    decryptedSize = encryptedSize;

    // Decrypt the data
    if (!CryptDecrypt(hKey, 0, TRUE, 0, &decryptedData[0], &decryptedSize)) {
        std::cerr << "CryptDecrypt failed: " << GetLastError() << std::endl;
        decryptedData.clear();
    } else {
        // Resize to actual decrypted size (removes padding)
        decryptedData.resize(decryptedSize);
    }

    // Clean up
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return decryptedData;
}

int main() {
    // Your encrypted data from the previous example
    BYTE encrypted[] = {0x8F, 0xCB, 0xFD, 0x91, 0x23, 0x4E, 0xEA, 0x06, 
                        0x59, 0xFE, 0x3F, 0x56, 0x38, 0x1B, 0x3B, 0x2F};
    
    // The same key used for encryption
    BYTE key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    std::vector<BYTE> decrypted = AESDecrypt(encrypted, sizeof(encrypted), key, sizeof(key));

    if (!decrypted.empty()) {
        std::cout << "Decrypted data: \"";
        for (BYTE b : decrypted) {
            printf("%c", b);
        }
        std::cout << "\"" << std::endl;
    } else {
        std::cerr << "Decryption failed!" << std::endl;
    }

    return 0;
}
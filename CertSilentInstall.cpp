#pragma comment(lib, "Crypt32")

#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <fstream>
#include <vector>
#include "WinCryptEx.h"

bool ImportCert(std::wstring filename, std::wstring password);

int wmain(int argc, wchar_t** argv)
{
    std::wcout << L"@ ITmindCo\n";
    std::wcout << L"Import pfx in silent mode\n";
    if (argc != 3) {
        std::wcout << L"use:\n";
        std::wcout << L"CertSilentInst <password> <filename>\n";
        return 0;
    }

    std::wstring pass = argv[1];
    std::wstring filename = argv[2];

    if (!ImportCert(filename, pass)) {
        DWORD err = GetLastError();
        std::wcout << L"Windows error kod: " << err;
        return 1;
    }

    return 0;
}

bool ReadCertFileToBLOB(std::wstring filename, CRYPT_DATA_BLOB& pData) {
    std::streampos fsize = 0;
    std::ifstream file(filename, std::ios::binary);
    if (file.fail()) {
        std::wcout << "error open file " << filename << "\n";
        return false;
    }
    fsize = file.tellg();
    file.seekg(0, std::ios::end);
    fsize = file.tellg() - fsize;
    file.seekg(0, std::ios::beg);

    pData.cbData = fsize;
    pData.pbData = new BYTE[pData.cbData];
    file.read((char*)pData.pbData, pData.cbData);
    file.close();

    return true;
}

bool ImportCert(std::wstring filename, std::wstring password)
{
    CRYPT_DATA_BLOB pData;
    if (!ReadCertFileToBLOB(filename, pData)) {
        return false;
    }
    
    HCERTSTORE hMemStore = PFXImportCertStore(&pData, password.c_str(), PKCS12_IMPORT_SILENT); // 
    if (!hMemStore) {
        return false;
    }

    HCERTSTORE hSystemStore;
    if (!(hSystemStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY")))
    {
        if (hMemStore)
            CertCloseStore(hMemStore, CERT_CLOSE_STORE_CHECK_FLAG);
        std::wcout << L"Could not open the MY system store.\n";
        return false;
    }

    PCCERT_CONTEXT certHandle = nullptr;
    while ((certHandle = CertEnumCertificatesInStore(hMemStore, certHandle)))
    {
        DWORD provinfosize = 0;
        PCRYPT_KEY_PROV_INFO provinfo = nullptr;

        if (CertGetCertificateContextProperty(certHandle, CERT_KEY_PROV_INFO_PROP_ID, provinfo, &provinfosize))
        {
            BOOL bFreeHandle;
            HCRYPTPROV hProv = NULL;
            DWORD dwKeySpec;
            BOOL bResult = CryptAcquireCertificatePrivateKey(certHandle, 0, NULL, &hProv, &dwKeySpec, &bFreeHandle);
            
            //выделим буфер в 100 байт
            char* mbstr = new char[100];
            size_t pReturnValue = 0;
            wcstombs_s(&pReturnValue, mbstr, 100, password.c_str(), 100);

            CRYPT_PIN_PARAM param;
            param.type = CRYPT_PIN_PASSWD;
            param.dest.passwd = mbstr;

            if (!CryptSetProvParam(hProv, PP_CHANGE_PIN, (BYTE*)&param, 0U)) {
                std::wcout << L"Could not change pin.\n";
                DWORD err = GetLastError();
                std::wcout << L"Windows error kod: " << err;
            }

            if (CertAddCertificateContextToStore(hSystemStore, certHandle, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
            {
                std::wcout << L"Certificate added to the memory store. \n";
            }
            else
            {
                std::wcout << L"Could not add the certificate to the memory store.\n";
                DWORD err = GetLastError();
                std::wcout << L"Windows error kod: " << err;
            }

            if (bFreeHandle) {
                CryptReleaseContext(hProv, 0);
            }            
        }

    }

    if (hMemStore)
        CertCloseStore(hMemStore, CERT_CLOSE_STORE_CHECK_FLAG);

    if (hSystemStore)
        CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG);

    return true;

}


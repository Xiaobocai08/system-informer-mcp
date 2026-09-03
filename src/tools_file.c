#include "ntutil.h"
#include "mcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

/* ---- file_details --------------------------------------------------------- */
static void add_version_info(cJSON *o, const char *path)
{
    PWSTR wpath = ntu_u2w(path);
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(wpath, &dummy);
    if (!size) { free(wpath); return; }
    void *buf = malloc(size);
    if (buf && GetFileVersionInfoW(wpath, 0, size, buf))
    {
        struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpt = NULL;
        UINT cb = 0;
        if (VerQueryValueW(buf, L"\\VarFileInfo\\Translation", (void **)&lpt, &cb) && cb >= sizeof(*lpt))
        {
            const wchar_t *fields[] = { L"CompanyName", L"FileDescription", L"FileVersion", L"ProductName", L"ProductVersion", L"OriginalFilename", L"LegalCopyright" };
            const char *keys[] = { "companyName", "fileDescription", "fileVersion", "productName", "productVersion", "originalFilename", "legalCopyright" };
            for (int i = 0; i < 7; i++)
            {
                WCHAR sub[128];
                _snwprintf_s(sub, 128, _TRUNCATE, L"\\StringFileInfo\\%04x%04x\\%s", lpt->wLanguage, lpt->wCodePage, fields[i]);
                PWSTR val = NULL; UINT vlen = 0;
                if (VerQueryValueW(buf, sub, (void **)&val, &vlen) && val && vlen)
                    ntu_add_w(o, keys[i], val);
            }
        }
    }
    free(buf);
    free(wpath);
}

static cJSON *tool_file_details(const cJSON *args, int *isError)
{
    const char *path = mcp_arg_str(args, "path", NULL);
    if (!path || !path[0]) { *isError = 1; return mcp_err_hint("Pass the file \"path\".", "Missing required argument: path"); }
    PWSTR wpath = ntu_u2w(path);
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(wpath, GetFileExInfoStandard, &fad))
    {
        DWORD e = GetLastError(); free(wpath);
        *isError = 1; return ntu_win_error("GetFileAttributesEx", e);
    }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "path", path);
    unsigned long long sz = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    ntu_add_bytes(o, "size", sz);
    cJSON_AddBoolToObject(o, "directory", (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0);
    cJSON_AddBoolToObject(o, "readonly", (fad.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 1 : 0);
    cJSON_AddBoolToObject(o, "hidden", (fad.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) ? 1 : 0);
    char t[32];
    ntu_time_to_iso(((LONG64)fad.ftCreationTime.dwHighDateTime << 32) | fad.ftCreationTime.dwLowDateTime, t, sizeof(t));
    cJSON_AddStringToObject(o, "created", t);
    ntu_time_to_iso(((LONG64)fad.ftLastWriteTime.dwHighDateTime << 32) | fad.ftLastWriteTime.dwLowDateTime, t, sizeof(t));
    cJSON_AddStringToObject(o, "modified", t);
    add_version_info(o, path);
    free(wpath);
    return o;
}

/* ---- verify_file_signature ------------------------------------------------ */
static char *cert_subject_name(const char *path)
{
    PWSTR wpath = ntu_u2w(path);
    HCERTSTORE store = NULL; HCRYPTMSG msg = NULL;
    char *result = NULL;
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &store, &msg, NULL))
    {
        DWORD si = 0;
        CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &si);
        if (si)
        {
            PCMSG_SIGNER_INFO signer = (PCMSG_SIGNER_INFO)malloc(si);
            if (signer && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signer, &si))
            {
                CERT_INFO ci; ci.Issuer = signer->Issuer; ci.SerialNumber = signer->SerialNumber;
                PCCERT_CONTEXT cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &ci, NULL);
                if (cert)
                {
                    DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
                    if (n > 1)
                    {
                        PWSTR name = (PWSTR)malloc(n * sizeof(WCHAR));
                        if (name && CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, n))
                            result = ntu_w2u(name, -1);
                        free(name);
                    }
                    CertFreeCertificateContext(cert);
                }
            }
            free(signer);
        }
    }
    if (msg) CryptMsgClose(msg);
    if (store) CertCloseStore(store, 0);
    free(wpath);
    return result;
}

static cJSON *tool_verify_file_signature(const cJSON *args, int *isError)
{
    const char *path = mcp_arg_str(args, "path", NULL);
    if (!path || !path[0]) { *isError = 1; return mcp_err_hint("Pass the file \"path\" to verify.", "Missing required argument: path"); }
    PWSTR wpath = ntu_u2w(path);

    WINTRUST_FILE_INFO fi; memset(&fi, 0, sizeof(fi));
    fi.cbStruct = sizeof(fi); fi.pcwszFilePath = wpath;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd; memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    free(wpath);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "path", path);
    int trusted = (status == 0);
    cJSON_AddBoolToObject(o, "signed", (status == 0 || status == (LONG)TRUST_E_NOSIGNATURE) ? (status == 0) : (status != (LONG)TRUST_E_NOSIGNATURE));
    cJSON_AddBoolToObject(o, "trusted", trusted);
    const char *verdict;
    switch ((DWORD)status)
    {
    case 0: verdict = "Valid: signed and trusted."; break;
    case (DWORD)TRUST_E_NOSIGNATURE: verdict = "Not signed (no embedded Authenticode signature)."; cJSON_ReplaceItemInObject(o, "signed", cJSON_CreateBool(0)); break;
    case (DWORD)TRUST_E_EXPLICIT_DISTRUST: verdict = "Signature explicitly distrusted."; break;
    case (DWORD)TRUST_E_SUBJECT_NOT_TRUSTED: verdict = "Signed but not trusted (untrusted root/publisher)."; break;
    case (DWORD)CRYPT_E_SECURITY_SETTINGS: verdict = "Signed; blocked by security policy."; break;
    case (DWORD)CERT_E_EXPIRED: verdict = "Signed but the certificate has expired."; break;
    case (DWORD)CERT_E_REVOKED: verdict = "Signed but the certificate was revoked."; break;
    default: verdict = "Signature invalid or verification failed."; break;
    }
    cJSON_AddStringToObject(o, "verdict", verdict);
    char code[16]; _snprintf_s(code, sizeof(code), _TRUNCATE, "0x%08lX", (unsigned long)status);
    cJSON_AddStringToObject(o, "statusCode", code);
    char *subject = cert_subject_name(path);
    if (subject) { cJSON_AddStringToObject(o, "signer", subject); free(subject); }
    return o;
}

/* ---- registration --------------------------------------------------------- */
static const Tool g_file_tools[] = {
    { "file_details", "File details",
      "Metadata for a file on disk: size, timestamps, attributes and (for signed binaries) version-resource "
      "fields - company, description, product, file/product version, original filename, copyright. Use to identify "
      "an executable found via process_details imagePath.",
      "{\"type\":\"object\",\"properties\":{"
      "\"path\":{\"type\":\"string\",\"description\":\"Full path to the file, e.g. \\\"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\notepad.exe\\\".\"}"
      "},\"required\":[\"path\"],\"additionalProperties\":false}", 0, tool_file_details },

    { "verify_file_signature", "Verify signature",
      "Verify a file's Authenticode digital signature with WinVerifyTrust (System Informer 'Verify'). Returns "
      "whether it is signed, whether the signature is trusted, a plain-language verdict, the raw status code, and "
      "the signer (certificate subject) name. The direct way to answer 'is this binary validly signed, and by "
      "whom?' during malware triage.",
      "{\"type\":\"object\",\"properties\":{"
      "\"path\":{\"type\":\"string\",\"description\":\"Full path to the file to verify.\"}"
      "},\"required\":[\"path\"],\"additionalProperties\":false}", 0, tool_verify_file_signature },
};

void register_file_tools(void)
{
    for (size_t i = 0; i < sizeof(g_file_tools) / sizeof(g_file_tools[0]); i++)
        mcp_register_tool(&g_file_tools[i]);
}

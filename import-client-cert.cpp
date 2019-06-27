#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

#include "nss.h"
#include "p12.h"
#include "p12plcy.h"
#include "pk11pub.h"
#include "prerror.h"

// Helper goop to turn some NSS types into RAII/unique_ptr types.
template <class T, void (*d)(T *)> struct UniqueMaybeDelete {
  void operator()(T *ptr) {
    if (ptr) {
      d(ptr);
    }
  }
};

#define UNIQUE(type, deleter)                                                  \
  typedef std::unique_ptr<type, UniqueMaybeDelete<type, deleter>> Unique##type;
UNIQUE(CERTCertificate, CERT_DestroyCertificate);
UNIQUE(PK11SlotInfo, PK11_FreeSlot);
UNIQUE(SEC_PKCS12DecoderContext, SEC_PKCS12DecoderFinish);
#undef UNIQUE

// Password prompt handler for situations where the NSS certificate/key database
// has a "master password" set. The caller takes ownership of the allocated
// memory.
char *passwordPrompt(PK11SlotInfo *slot, PRBool retry, void *arg) {
  std::cout << "NSS cert/key DB password: ";
  std::string password;
  std::cin >> password;
  return strdup(password.c_str());
}

void printPRError(const char *prefix) {
  std::cerr << prefix << " failed: " << PR_ErrorToString(PR_GetError(), 0)
            << "\n";
}

// When importing new certificates, they may either not have a nickname set or
// the nickname may collide with an existing certificate. This function attempts
// to find a unique nickname and returns it if it can. This function makes no
// attempt to find a particularly useful nickname, however.
SECItem *nicknameCollision(SECItem *oldNickname, PRBool *cancel, void *) {
  *cancel = true;

  char nickname[64];
  for (size_t i = 0; i < 65536; i++) {
    snprintf(nickname, sizeof(nickname), "imported cert #%lu", i);
    UniqueCERTCertificate cert(
        CERT_FindCertByNickname(CERT_GetDefaultCertDB(), nickname));
    // If there is no existing certificate using this nickname, we can use it.
    if (!cert) {
      *cancel = false;
      SECItem *nicknameItem =
          SECITEM_AllocItem(nullptr, nullptr, strlen(nickname) + 1);
      memcpy(nicknameItem->data, nickname, nicknameItem->len);
      return nicknameItem;
    }
  }

  return nullptr;
}

// Helper to read the password that encrypted the PKCS#12 file (this really only
// handles ASCII).
std::string promptPKCS12Password() {
  std::cout << "PKCS12 password: ";
  std::string password;
  std::cin >> password;
  return password;
}

// The password-based encryption in use requires a big endian unicode string for
// some reason.
std::vector<uint8_t> passwordToPKCS12String(std::string password) {
  std::vector<uint8_t> wide(2 * (password.size() + 1), 0);
  for (size_t i = 0; i < password.size(); i++) {
    wide[(2 * i) + 1] = password[i];
  }
  return wide;
}

int tryToImportCert(const char *pathToCert) {
  UniquePK11SlotInfo slot(PK11_GetInternalKeySlot());
  if (PK11_NeedUserInit(slot.get())) {
    // This sets an empty password on the NSS db, like 99% of Firefox users.
    if (PK11_InitPin(slot.get(), nullptr, nullptr) != SECSuccess) {
      printPRError("PK11_InitPin");
      return 1;
    }
  }

  std::vector<uint8_t> password(passwordToPKCS12String(promptPKCS12Password()));
  SECItem passwordItem = {siBuffer, password.data(),
                          static_cast<unsigned int>(password.size())};
  UniqueSEC_PKCS12DecoderContext ctx(
      SEC_PKCS12DecoderStart(&passwordItem, slot.get(), nullptr, nullptr,
                             nullptr, nullptr, nullptr, nullptr));
  if (!ctx) {
    printPRError("SEC_PKCS12DecoderStart");
    return 1;
  }

  std::ifstream pkcs12File(pathToCert,
                           std::ios::in | std::ios::binary | std::ios::ate);
  if (!pkcs12File.is_open()) {
    std::cerr << "couldn't open " << pathToCert << "\n";
    return 1;
  }
  std::streampos size = pkcs12File.tellg();
  pkcs12File.seekg(0, std::ios::beg);
  std::unique_ptr<uint8_t[]> contents(new uint8_t[size]);
  pkcs12File.read(reinterpret_cast<char *>(contents.get()), size);
  pkcs12File.close();
  SECStatus srv = SEC_PKCS12DecoderUpdate(ctx.get(), contents.get(), size);
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderUpdate");
    return 1;
  }

  srv = SEC_PKCS12DecoderVerify(ctx.get());
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderVerify");
    return 1;
  }

  srv = SEC_PKCS12DecoderValidateBags(ctx.get(), nicknameCollision);
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderValidateBags");
    return 1;
  }

  srv = SEC_PKCS12DecoderImportBags(ctx.get());
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderImportBags");
    return 1;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0]
              << " <path to Firefox profile> <pkcs12 file to import>\n";
    return 1;
  }
  if (NSS_Initialize(argv[1], "", "", SECMOD_DB, NSS_INIT_NOROOTINIT) !=
      SECSuccess) {
    printPRError("NSS_Initialize");
    return 1;
  }

  // These are all rather old, but it's what Firefox enables.
  SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
  SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
  SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
  SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);

  PK11_SetPasswordFunc(passwordPrompt);

  int result = tryToImportCert(argv[2]);

  if (NSS_Shutdown() != SECSuccess) {
    printPRError("NSS_Shutdown");
    return 1;
  }

  std::cout << (result == 0 ? "success" : "failure") << "\n";

  return result;
}

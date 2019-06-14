#include <fstream>
#include <iostream>

#include "nss.h"
#include "p12.h"
#include "p12plcy.h"
#include "pk11pub.h"
#include "prerror.h"

char *passwordPrompt(PK11SlotInfo *slot, PRBool retry, void *arg) {
  std::cerr << "password prompt\n";
  return strdup("password");
}

void printPRError(const char *prefix) {
  std::cerr << prefix << " failed: " << PR_ErrorToString(PR_GetError(), 0)
            << "\n";
}

SECItem *nicknameCollision(SECItem *oldNickname, PRBool *cancel, void *) {
  *cancel = true;

  char nickname[64];
  for (size_t i = 0; i < 65536; i++) {
    snprintf(nickname, sizeof(nickname), "imported cert #%lu", i);
    CERTCertificate *cert(
        CERT_FindCertByNickname(CERT_GetDefaultCertDB(), nickname));
    if (!cert) {
      *cancel = false;
      SECItem *nicknameItem =
          SECITEM_AllocItem(nullptr, nullptr, strlen(nickname));
      memcpy(nicknameItem->data, nickname, nicknameItem->len);
      return nicknameItem;
    }
  }

  return nullptr;
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

  SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
  SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
  SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
  SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);

  PK11_SetPasswordFunc(passwordPrompt);

  PK11SlotInfo *slot = PK11_GetInternalKeySlot();
  if (PK11_NeedUserInit(slot)) {
    // This just sets an empty password on the NSS db, like 99% of Firefox
    // users.
    if (PK11_InitPin(slot, nullptr, nullptr) != SECSuccess) {
      printPRError("PK11_InitPin");
      return 1;
    }
  }

  uint8_t nulls[] = {0, 0};
  SECItem nullPassword = {siBuffer, nulls, sizeof(nulls)};
  // SECItem nullPassword = { siBuffer, nullptr, 0 };
  SEC_PKCS12DecoderContext *ctx(
      SEC_PKCS12DecoderStart(&nullPassword, slot, nullptr, nullptr, nullptr,
                             nullptr, nullptr, nullptr));
  if (!ctx) {
    printPRError("SEC_PKCS12DecoderStart");
    return 1;
  }

  std::ifstream pkcs12File(argv[2],
                           std::ios::in | std::ios::binary | std::ios::ate);
  if (!pkcs12File.is_open()) {
    std::cerr << "couldn't open " << argv[2] << "\n";
    return 1;
  }
  std::streampos size = pkcs12File.tellg();
  pkcs12File.seekg(0, std::ios::beg);
  uint8_t *contents = new uint8_t[size];
  pkcs12File.read(reinterpret_cast<char *>(contents), size);
  pkcs12File.close();
  SECStatus srv = SEC_PKCS12DecoderUpdate(ctx, contents, size);
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderUpdate");
    return 1;
  }

  srv = SEC_PKCS12DecoderVerify(ctx);
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderVerify");
    return 1;
  }

  srv = SEC_PKCS12DecoderValidateBags(ctx, nicknameCollision);
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderValidateBags");
    return 1;
  }

  srv = SEC_PKCS12DecoderImportBags(ctx);
  if (srv != SECSuccess) {
    printPRError("SEC_PKCS12DecoderImportBags");
    return 1;
  }

  PK11_FreeSlot(slot);

  if (NSS_Shutdown() != SECSuccess) {
    printPRError("NSS_Shutdown");
    return 1;
  }
  return 0;
}

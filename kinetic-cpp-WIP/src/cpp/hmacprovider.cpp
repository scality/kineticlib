#include <iostream>
#include <errno.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <nan.h>

#include "put.h"
#include "hmacprovider.h"
#include "errorProp.h"
#include "kinetic.pb.h"

using com::seagate::kinetic::proto::Command;
using com::seagate::kinetic::proto::Message;
using namespace std;


std::string computeHmac(const Message& message, const std::string& key) {

  HMAC_CTX ctx;

  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, key.c_str(), key.length(), EVP_sha1(), NULL);
  uint32_t message_length_bigendian = htonl(message.commandbytes().length());
  HMAC_Update(&ctx, reinterpret_cast<unsigned char *>(&message_length_bigendian),
              sizeof(uint32_t));
  HMAC_Update(&ctx,
              reinterpret_cast<const unsigned char *>(message.
                                                      commandbytes().
                                                      c_str()),
              message.commandbytes().length());

  unsigned char result[SHA_DIGEST_LENGTH];
  unsigned int result_len = SHA_DIGEST_LENGTH;

  HMAC_Final(&ctx, result, &result_len);
  HMAC_CTX_cleanup(&ctx);

  return std::string(reinterpret_cast<char *>(result), result_len);
}

bool validateHmac(const Message& message,
                  const std::string& key) {
  std::string correct_hmac(computeHmac(message, key));

  if (!message.has_hmacauth()) {
    return false;
  }

  const std::string &provided_hmac = message.hmacauth().hmac();

  if (provided_hmac.length() != correct_hmac.length()) {
    return false;
  }

  int result = 0;
  for (size_t i = 0; i < correct_hmac.length(); i++) {
    result |= provided_hmac[i] ^ correct_hmac[i];
  }

  return result == 0;
}

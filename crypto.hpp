#ifndef _CRYPTO_HPP_
#define _CRYPTO_HPP_

#include <string>
#include "openssl/rsa.h"

#define CRYPTO_DEBUG 0

enum CRYPTO_RESULT {
  CRYPTO_SUCCESS    , /* 0 */
  CRYPTO_ERROR      , /* 1 */
  CRYPTO_BAD_LENGTH , /* 2 */
};

class Crypto {
private:
  RSA *rsa_pub;
  RSA *rsa_priv;
  EVP_PKEY *evp_rsa_pub;
  EVP_PKEY *evp_rsa_priv;

  int crypto_en;
  unsigned long seq_num;
  void init_pubkey();
  void init_privkey();
  
public:
  Crypto();
  ~Crypto();
  CRYPTO_RESULT b64_encode(const unsigned char *in, int len, std::string &out);
  CRYPTO_RESULT b64_decode(std::string const &in, unsigned char **out, int &out_len);
  CRYPTO_RESULT encrypt_and_b64(std::string &msg_b64, std::string &ek_b64, std::string &iv_b64, std::string &out);
  CRYPTO_RESULT db64_and_decrypt(std::string const &msg_b64, std::string const &ek_b64, std::string const &iv_b64, std::string &out);
  CRYPTO_RESULT get_md5(std::string const &in, std::string &md5);
  CRYPTO_RESULT get_sha256(std::string const &in, std::string &sha256);
};

std::string crypto_result_str(CRYPTO_RESULT rv);

#endif /* _CRYPTO_HPP_ */

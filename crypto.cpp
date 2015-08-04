#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <string.h>
#include <cmath>

#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/md5.h"
#include "openssl/sha.h"

#include "crypto.hpp"

extern const char *test_rsa_pubkey_pem;
extern const char *test_rsa_privkey_pem;

/*! \brief Default constructor for the Crypto class
 */
Crypto::Crypto()
{
  seq_num = 0;
  evp_rsa_pub = NULL;
  rsa_pub = NULL;
  rsa_priv = NULL;
  evp_rsa_priv = NULL;
  
  init_pubkey();
  init_privkey();
}

/*! \brief Default destructor for the Crypto class
 */
Crypto::~Crypto()
{
  if (evp_rsa_pub)
    EVP_PKEY_free(evp_rsa_pub);

  if (rsa_pub)
    free(rsa_pub);

  if (evp_rsa_priv)
    EVP_PKEY_free(evp_rsa_priv);

  CRYPTO_cleanup_all_ex_data();
}

/*! \brief Create RSA public key container to use during encryption
 */
void Crypto::init_pubkey()
{
  void *rsa_pubkey_pem_buf;
  rsa_pubkey_pem_buf = (void *)test_rsa_pubkey_pem;
  
  if (CRYPTO_DEBUG) {
    std::cout << "DEBUG: init_pubkey(): rsa_pubkey_pem_buf: " 
	      << (char *)rsa_pubkey_pem_buf << std::endl;
  }

  /* The public key is in a cpp file (nvcrypto_pem_pubkey.cpp) in 
   * char * format and we use BIO to eventually create an RSA object
   */
  BIO *bio = BIO_new_mem_buf(rsa_pubkey_pem_buf, -1);
  RSA *rsa_pub = NULL;
  if (! PEM_read_bio_RSA_PUBKEY(bio, &rsa_pub, 0, NULL) ) {
    ERR_print_errors_fp(stderr);
    BIO_free(bio);
    throw std::runtime_error("Crypto::init_pubkey(): Could not init rsa object, stopping.");
  }
  BIO_free(bio);

  /* To use EVP functions, we need the key to be of EVP_PKEY type. The next 
   * block of code copies the RSA key into the EVP_PKEY object
   */
  evp_rsa_pub = EVP_PKEY_new();
  if (evp_rsa_pub == NULL) {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("Crypto::init_pubkey(): Could not allocate memory for EVP_PKEY, stopping.");
  }
  
  if (!EVP_PKEY_assign_RSA(evp_rsa_pub, rsa_pub)) {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("Crypto::init_pubkey(): Could not assign RSA key, stopping.");
  }
  return;
}

/*! \brief Create RSA Private key containers for use in decryption
 */
void Crypto::init_privkey()
{
  if (CRYPTO_DEBUG) {
    std::cout << "DEBUG: init_privkey(): rsa_privkey_pem: "
	      << (char *)test_rsa_privkey_pem << std::endl;
  }

  /* The private key is in a cpp file (nvcrypto_pem_pubkey.cpp) in 
   * char * format and we use BIO to eventually create an RSA object
   */
  BIO *bio = BIO_new_mem_buf((void *)test_rsa_privkey_pem, -1);
  rsa_priv = NULL;
  if (! PEM_read_bio_RSAPrivateKey(bio, &rsa_priv, 0, NULL) ) {
    ERR_print_errors_fp(stderr);
    BIO_free(bio);
    throw std::runtime_error("Crypto::init_privkey(): Could not create debug key, stopping.");
  }
  BIO_free(bio);

  /* To use EVP functions, we need the key to be of EVP_PKEY type. The next 
   * block of code copies the RSA key into the EVP_PKEY object
   */
  evp_rsa_priv = EVP_PKEY_new();
  if (! EVP_PKEY_assign_RSA(evp_rsa_priv, rsa_priv) ){
    ERR_print_errors_fp(stderr);
    free(rsa_priv);
    std::cout <<"FREEING rsa_priv" << std::endl;
    EVP_PKEY_free(evp_rsa_priv);
  }

  return;
}

/*! \brief Encodes an unsigned char array in of length len to base64 format 
 * and writes the result to a C++ string
 */
CRYPTO_RESULT Crypto::b64_encode(const unsigned char *in, int len, std::string &out)
{
  if (len==0) {
    std::cout << "WARNING: Crypto::b64_encode(): Input string has 0 length" << std::endl;
    out = "";
    return CRYPTO_BAD_LENGTH;
  }
  
  BIO *bmem, *b64;
  BUF_MEM *bptr;
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64, in, len);
  (void) BIO_flush(b64); /* Silence compiler with (void) cast */
  BIO_get_mem_ptr(bmem, &bptr);
  char *buf = (char *)malloc(bptr->length+1);
  memcpy(buf, bptr->data, bptr->length);
  buf[bptr->length]=0;

  out.append(buf);

  if (CRYPTO_DEBUG) {
    std::cout << "Crypto::b64_encode(): input size=(" << len << "), output=("
	      << out << ")." << std::endl;
  }
  
  free(buf);
  BIO_free_all(b64);
  
  return CRYPTO_SUCCESS;
}

/*! \brief Decodes a C++ string containing a base64 message and writes the 
 * raw bytes into a unsigned char array along with the length to an int 
 *(out_len)
 */
CRYPTO_RESULT Crypto::b64_decode(std::string const &in, unsigned char **out, int &out_len)
{
  if (in.empty() ) {
    std::cout << "WARNING: Crypto::b64_decode(): Input string has 0 length"
	      << std::endl;
    return CRYPTO_BAD_LENGTH;
  }
  
  BIO *bmem, *b64;
  
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf((char *)in.c_str(), -1);
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  int in_sz = int(in.size());
  out_len = BIO_read(b64, *out, in_sz);

  if (CRYPTO_DEBUG) {
    std::cout << "DEBUG: Crypto::b64_decode(): input=(" << in
	      << "), output size=(" << out_len << ")." << std::endl;
  }

  /*  Sanity check */
  if (CRYPTO_DEBUG) {
    int num_actual_b64_chars = int(in.find_first_of("=", 0)) - 1;
    int num_exp_raw_chars = ceil((num_actual_b64_chars * 6)/8);
    std::cout << "DEBUG: Crypto::b64_decode(): exp len = " << num_exp_raw_chars
	      << ", actual len = " << out_len
	      << " ok = " << (num_exp_raw_chars == out_len) << std::endl;
  }
  BIO_free_all(b64);
  return CRYPTO_SUCCESS;
}

/* \brief External API to encrypt - encrypts input C++ string and writes 3 base64 encoded output parameters
 * 
 * \param[out] msg_b64 - encrypted message, base64 encoded
 * \param[out] ek_b64 - encrypted AES key, base64 encoded
 * \param[out] iv_b64 - IV, base64 encoded
 */
CRYPTO_RESULT Crypto::encrypt_and_b64(std::string &input, std::string &msg_b64, std::string &ek_b64, std::string &iv_b64)
{
  unsigned char output[input.size() + EVP_MAX_IV_LENGTH];
  int output_len=0, tmp_len=0;

  /* Let's ensure input is a multiple of 16 */
  int r = int(input.size() % 16);
  if (r) {
    input.append(16-r, '@');
  }

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  
  unsigned char *ek = (unsigned char *)malloc(EVP_PKEY_size(evp_rsa_pub));
  int ek_len=0;
  if (ek == NULL) {
    /* Could not allocate memory */
    throw std::runtime_error("Crypto::encrypt_and_b64(): Could not allocate memory for AES key, stopping.");
  }

  unsigned char *iv = (unsigned char *)malloc(EVP_MAX_IV_LENGTH);
  int iv_len=0;
  if (iv == NULL) {
    /* Could not allocate memory */
    throw std::runtime_error("Crypto::encrypt_and_b64(): Could not allocate memory for IV, stopping.");
  }

  /* This sets up the encryption - it generates a random AES key and IV. The AES key (ek) is 
   * encrypted with the RSA public key. It populates the context (ctx) with the necessary 
   * containers to actually encrypt the message.
   * Here, I use AES in CBC mode with a 128bit key
   */
  if (!EVP_SealInit(&ctx, EVP_aes_128_cbc(), &ek, &ek_len, iv, &evp_rsa_pub, 1)) {
    ERR_print_errors_fp(stderr);
  }

  iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
  
  if (!EVP_SealUpdate(&ctx, output, &tmp_len, (unsigned char *)input.c_str(), input.size()) ) {
    throw std::runtime_error("Crypto::encrypt_and_b64(): Could not run EVP_SealUpdate(), stopping.");
  }
  output_len += tmp_len;

  if (!EVP_SealFinal(&ctx, output+tmp_len, &tmp_len) ) {
    throw std::runtime_error("Crypto::encrypt_and_b64(): Could not run EVP_SealFinal(), stopping.");
  }
  output_len += tmp_len;
  
  b64_encode(output, output_len, msg_b64);
 
  /* ek and iv can both contain non-printable characters, so we convert 
   * to b64 */
  b64_encode(ek, ek_len, ek_b64);
  b64_encode(iv, iv_len, iv_b64);

  if (CRYPTO_DEBUG) {
    std::cout << "DEBUG: Crypto::encrypt_and_b64(): msg_b64=" << msg_b64
	      << ", ek_b64=" <<  ek_b64 << ", iv_b64=" << iv_b64
	      << std::endl;
  }

  EVP_CIPHER_CTX_cleanup(&ctx);
  free(ek);
  free(iv);
  return CRYPTO_SUCCESS;
}

/*! \brief External API to decrypt, takes 3 base64 encoded parameters and writes to an output C++ string
 * \param[in], msg_b64 - encrypted message in base64
 * \param[in], ek_b64 - encrypted AES key in base64
 * \param[in], iv_b64 - encrypted AES IV in base64
 */
CRYPTO_RESULT Crypto::db64_and_decrypt(std::string const &msg_b64, std::string const &ek_b64, std::string const &iv_b64, std::string &out)
{
  EVP_CIPHER_CTX ctxd;
  EVP_CIPHER_CTX_init(&ctxd);

  unsigned char *msg_e = (unsigned char *)malloc(10000);
  int msg_e_len=0;
  b64_decode(msg_b64, &msg_e, msg_e_len);
  
  unsigned char *ek = (unsigned char *)malloc(EVP_PKEY_size(evp_rsa_priv));
  int ek_len=0;
  if (ek == NULL) {
    /* Could not allocate memory */
    throw std::runtime_error("Crypto::db64_and_decrypt(): Could not allocate memory for AES key, stopping.");
  }

  b64_decode(ek_b64, &ek, ek_len);

  unsigned char *iv = (unsigned char *)malloc(EVP_MAX_IV_LENGTH);
  int iv_len=0;
  if (iv == NULL) {
    /* Could not allocate memory */
    throw std::runtime_error("Crypto::db64_and_decrypt(): Could not allocate memory for IV, stopping.");
  }

  /* This sets up the decryption - it takes the supplied encrypted AES key and IV 
   *  along with the RSA private key
   */
  b64_decode(iv_b64, &iv, iv_len);
    
  if (!EVP_OpenInit(&ctxd, EVP_aes_128_cbc(), ek, ek_len, iv, evp_rsa_priv)) {
    std::cout << "ERROR: db64_and_decrypt(): EVP_OpenInit failed" << std::endl;
    ERR_print_errors_fp(stderr);
  }

  unsigned char *out_buf = (unsigned char *)malloc(10000);
  int out_buf_len=0;
  if (!EVP_OpenUpdate(&ctxd, out_buf, &out_buf_len, msg_e, msg_e_len) ) {
    std::cout << "ERROR: db64_and_decrypt(): EVP_OpenUpdate failed" << std::endl;
    ERR_print_errors_fp(stderr);
  }
    
  if (out_buf_len > msg_e_len) {
    out.append((const char *)out_buf, msg_e_len);
  }
  else {
    out.append((const char *)out_buf, out_buf_len);
    
    if (!EVP_OpenFinal(&ctxd, out_buf, &out_buf_len) ){
      std::cout << "ERROR: EVP_OpenFinal failed" << std::endl;
      ERR_print_errors_fp(stderr);
    }
    if (out_buf_len)
      out.append((const char *)out_buf, out_buf_len);
  }

  EVP_CIPHER_CTX_cleanup(&ctxd);
  free (out_buf);
  free (msg_e);
  free (ek);
  free (iv);
  return CRYPTO_SUCCESS;
}

CRYPTO_RESULT Crypto::get_md5(std::string const &in, std::string &md5)
{
  unsigned char buf[MD5_DIGEST_LENGTH];
  
  MD5((unsigned char *)in.c_str(), in.size(), buf);
  return CRYPTO_SUCCESS;
}

CRYPTO_RESULT Crypto::get_sha256(std::string const &in, std::string &sha256)
{
  unsigned char buf[SHA256_DIGEST_LENGTH];

  SHA256((unsigned char *)in.c_str(), in.size(), buf);

  return CRYPTO_SUCCESS;
}

std::string crypto_result_str(CRYPTO_RESULT rv)
{
  std::string rvs;
  switch (rv) {
  case CRYPTO_SUCCESS: rvs = "CRYPTO_SUCCESS"; break;
  case CRYPTO_ERROR: rvs = "CRYPTO_ERROR"; break;
  case CRYPTO_BAD_LENGTH: rvs = "CRYPTO_BAD_LENGTH"; break;
  default: rvs = "CRYPTO_UNKNOWN"; break;
  }
  return rvs;
}

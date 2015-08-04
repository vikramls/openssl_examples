#include <iostream>
#include <iomanip>
#include <sstream>

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/sha.h"
#include "openssl/md5.h"

#include "crypto.hpp"

using namespace std;

int test_md5()
{
  string in1("foobar\n");
  string in2("hello\n");

  stringstream ss;
  size_t i=0;
  unsigned char buf[MD5_DIGEST_LENGTH];

  MD5((unsigned char *)in1.c_str(), in1.size(), buf);
  ss << hex;
  for (i=0; i<MD5_DIGEST_LENGTH; i++) {
    ss << setw(2) << setfill('0') << int(buf[i]);
  }

  cout << "in1:" << in1 << " -> " << ss.str() << endl;
  ss << dec;
  ss.str(""); ss.clear();
  cout << "Check output with 'echo \"" << "foobar" << "\" | openssl md5" << endl;

  MD5((unsigned char *)in2.c_str(), in2.size(), buf);
  ss << hex;
  for (i=0; i<MD5_DIGEST_LENGTH; i++) {
    ss << setw(2) << setfill('0') << int(buf[i]);    
  }

  cout << "in2:" << in2 << " -> " << ss.str() << endl;
  ss << dec;
  ss.str(""); ss.clear();

  cout << "Check output with 'echo \"" << "hello" << "\" | openssl md5" << endl;

  return 0;
  
}

int test_sha256()
{
  string in1("foobar\n");
  string in2("hello\n");
  stringstream ss;
  size_t i=0;
  unsigned char buf[SHA256_DIGEST_LENGTH];

  SHA256((unsigned char *)in1.c_str(), in1.size(), buf);
  ss << hex;
  for (i=0; i<SHA256_DIGEST_LENGTH; i++) {
    ss << setw(2) << setfill('0') << int(buf[i]);
  }

  cout << "in1:" << in1 << " -> " << ss.str() << endl;
  ss << dec;
  ss.str(""); ss.clear();
  cout << "Check output with 'echo \"" << "foobar" << "\" | openssl sha -sha256" << endl;

  SHA256((unsigned char *)in2.c_str(), in2.size(), buf);
  ss << hex;
  for (i=0; i<SHA256_DIGEST_LENGTH; i++) {
    ss << setw(2) << setfill('0') << int(buf[i]);    
  }

  cout << "in2:" << in2 << " -> " << ss.str() << endl;
  ss << dec;
  ss.str(""); ss.clear();

  cout << "Check output with 'echo \"" << "hello" << "\" | openssl sha -sha256" << endl;

  return 0;
}

int test_b64()
{
  Crypto cr;
  string a, b, c;
  string xa("foobar");
  cr.b64_encode((unsigned char *)xa.c_str(), 7, a);
  string xb("0123456789abcdefg");
  cr.b64_encode((unsigned char *)xb.c_str(), 17, b);  
  string xc("hello world...");
  cr.b64_encode((unsigned char *)xc.c_str(), 14, c);

  cout << "xa=" << xa << ", a=" << a << endl;
  cout << "xb=" << xb << ", b=" << b << endl;
  cout << "xc=" << xc << ", c=" << c << endl;  

  return 0;
}

int test_encr_decr()
{
  CRYPTO_RESULT rv=CRYPTO_SUCCESS;

  std::string in("HELLO, WORLD! WELCOME TO OUR OPENSSL OVERLORDS!!");
  std::cout << "INFO: PLAINTEXT=" << in << ", size=" << in.size() << endl;
  std::string msg_b64, ek_b64, iv_b64;

  Crypto cr;

  rv = cr.encrypt_and_b64(in, msg_b64, ek_b64, iv_b64);
  if (CRYPTO_DEBUG) {
    std::cout << "DEBUG: rv after encrypt = " << crypto_result_str(rv) << std::endl;
  }

  std::cout << "INFO: base64(MSG)=" << msg_b64 << std::endl;
  std::cout << "INFO: base64(KEY)=" << ek_b64 << std::endl;
  std::cout << "INFO: base64(IV)=" << iv_b64 << std::endl;
  
  string out("");
  rv = cr.db64_and_decrypt(msg_b64, ek_b64, iv_b64, out);
  if (CRYPTO_DEBUG) {
    std::cout << "DEBUG: rv after decrypt = " << crypto_result_str(rv) << endl;
  }
  
  std::cout << "INFO: DECRYPTED=" << out << ", size=" << out.size() << endl;
  
  return 0;
}

int main()
{
  test_encr_decr();
  test_md5();
  test_sha256();
  return 0;
}

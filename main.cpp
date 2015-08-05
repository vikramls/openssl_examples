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
  string in1("foobar"), in1_md5;
  string in2("hello"), in2_md5;

  Crypto cr;
  cr.get_md5(in1, in1_md5);
  
  cout << "INFO: md5(" << in1 << ") = " << in1_md5 << endl;
  cout << "INFO: Check output with 'echo -n \"" << in1 << "\" | openssl md5" << endl;

  cr.get_md5(in2, in2_md5);
    
  cout << "INFO: md5(" << in2 << ") =  " << in2_md5 << endl;
  cout << "INFO: Check output with 'echo -n \"" << in2 << "\" | openssl md5" << endl;
  return 0;
}

int test_sha256()
{
  string in1("foobar");
  string in1_sha256;
  string in2("hello");
  string in2_sha256;

  Crypto cr;
  cr.get_sha256(in1, in1_sha256);
  cout << "INFO: sha256(" << in1 << ") = " << in1_sha256 << endl; 
  cout << "INFO: Check output with 'echo -n \"" << in1 << "\" | openssl sha -sha256" << endl;
  cr.get_sha256(in2, in2_sha256);
  cout << "INFO: sha256(" << in2 << ") =  " << in2_sha256 << endl; 
  cout << "INFO: Check output with 'echo -n \"" << in2 << "\" | openssl sha -sha256" << endl;

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

  std::string in("HELLO, WORLD! WELCOME TO OUR OPENSSL OVERLORDS!!!!!");
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

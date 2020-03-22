#ifndef RSA_CLASS_H
#define RSA_CLASS_H

#include <string>
#include <vector>
#include <gmp.h>

class rsaCrypt
{
private:
    unsigned int crypt_bitnum;
    unsigned int blocksize;
    mpz_t lowerBound;
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t phi;
    mpz_t e;
    mpz_t d;

public:
    rsaCrypt(unsigned int c_bitnum);
    void rsaGenPrimes();
    void PrintPrimes();
    unsigned int getBitNum();
    bool rsaGenKeys();
    void PrintPublicKey();
    void Print_n_phi_e();
    void PrintPrivateKey();
    void rsaCleanup();

    void rsaEncryptBlock(std::vector<unsigned char>& source_block, std::vector<unsigned char>& target_block, unsigned int blocksize);
    void rsaDecryptBlock(std::string& readnumber, std::vector<unsigned char>& target_block, unsigned int chunksize);
    void rsaEncryptNum(std::string& numbuf_bin, std::string& encryptednum);
    void rsaDecryptNum(std::string& source_dec, std::string& target_bin);

    bool WritePublicKeyToFile(std::string& filepath);
    bool ReadPublicKeyFromFile(std::string& filepath, std::string& n, std::string& e);
    bool WritePrivateKeyToFile(std::string& filepath);
    bool ReadPrivateKeyFromFile(std::string& filepath, std::string& n, std::string& d);
    bool WriteCiphertextToFile(std::string& filepath, std::string& ciphertext);
//    bool ReadCiphertextFromFile(std::string& filepath, unsigned int& bitnum, std::string& storage);
//    bool ReadCleartextFromFile(std::string& filepath, std::string& msg_to_encrypt);

    // encrypt/decrypt whole file
    unsigned int EncryptFile(std::string& filepath, std::string& targetpath, unsigned int chunksize);
    unsigned int DecryptFile(std::string& filepath, std::string& targetpath, unsigned int chunksize);
};


#endif // RSA_CLASS_H

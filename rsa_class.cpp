// RSA_CLASS_CPP //
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <iterator>
#include <time.h>
#include "rsa_class.h"
#include "tools.h"

using namespace std;

rsaCrypt::rsaCrypt(unsigned int c_bitnum)
{
    crypt_bitnum = c_bitnum;
    blocksize = crypt_bitnum / 8;
}

void rsaCrypt::rsaGenPrimes()
{
    unsigned long int seed;
    gmp_randstate_t r_state;

    mpz_init(p);
    mpz_init(q);


    // create a random seed
    srand(time(NULL));
    seed = time(NULL) % rand()*10;
    //cout << "seed: " << seed << endl;

    // intitialize random "state"
    gmp_randinit_default (r_state);
    gmp_randseed_ui(r_state, seed);

    // primes have to be greater than sqrt(2^bitnum)
    mpz_t lowerBound; mpz_init(lowerBound);
    mpz_t pow_2_bitnum; mpz_init(pow_2_bitnum);

    mpz_ui_pow_ui(pow_2_bitnum, 2, this->getBitNum());
    mpz_sqrt(lowerBound, pow_2_bitnum);


    //gmp_printf("lowerBound: %Zd\n", lowerBound);

    // add arbitrarily high random number to lowerBound (here we just take number < 2^(bitnum-1) )
    mpz_t addrandom, rndSum;
    mpz_init(addrandom);
    mpz_init(rndSum);

    mpz_urandomb(addrandom, r_state, this->getBitNum()-1);
    //gmp_printf("addrandom: %Zd\n", addrandom);

    mpz_add(rndSum, lowerBound, addrandom);
    //gmp_printf("rndSum: %Zd\n", rndSum);

    // get next prime number
    mpz_nextprime(p, rndSum);

    // do the preceding again for p
    mpz_urandomb(addrandom, r_state, this->getBitNum()-1);
    //gmp_printf("addrandom: %Zd\n", addrandom);

    mpz_add(rndSum, lowerBound, addrandom);
    //gmp_printf("rndSum: %Zd\n", rndSum);
    mpz_nextprime(q, rndSum);

    // clear random "state"
    gmp_randclear(r_state);
    // clear variables
    mpz_clear(addrandom);
    mpz_clear(rndSum);
}

void rsaCrypt::PrintPrimes()
{
    gmp_printf("p: %Zd\n", p);
    gmp_printf("q: %Zd\n", q);
}

unsigned int rsaCrypt::getBitNum()
{
    return crypt_bitnum;
}

bool rsaCrypt::rsaGenKeys()
{
    mpz_init(n);
    mpz_init(phi);
    mpz_init(e);

    // generate n
    mpz_mul(n, p, q);
    if(!(mpz_cmp(n, lowerBound) > 0))
    {
        // gmp_printf("error, n: %Zd\n", n);
        return false;
    }

    // generate phi
    mpz_t p_buf, q_buf;
    mpz_init(p_buf); mpz_init(q_buf);

    mpz_sub_ui(p_buf, p, 1);
    mpz_sub_ui(q_buf, q, 1);

    mpz_mul(phi, p_buf, q_buf);
    if(mpz_cmp_ui(phi, 0) < 0 || mpz_cmp_ui(phi, 0) == 0)
    {
        gmp_printf("error, phi: %Zd\n", phi);
        return false;
    }

    // private key -> generate d (modular inverse)
    while(1) // repeat, if invert failed
    {
        // generate e, just pick 3, 5, 17, 256 or 65537
        unsigned int buf = (unsigned int) rand() % 5;
        switch(buf)
        {
            case 0: mpz_set_ui(e, 3);
            break;
            case 1: mpz_set_ui(e, 5);
            break;
            case 2: mpz_set_ui(e, 17);
            break;
            case 3: mpz_set_ui(e, 256);
            break;
            case 4: mpz_set_ui(e, 65537);
            break;
            default: cout << "error no e found, rand() did not work" << endl;
                     return false;
            break;
        }

        mpz_t tmp1; mpz_init(tmp1);
        mpz_init(d);

        unsigned int counter = 0;
        if(mpz_invert(d, e, phi) == 0)
        {
            mpz_gcd(tmp1, e, phi);
            // printf("Invert failed\n");
            // printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
            counter++;

            if(counter > 100)
                return false;
            continue;
        }
        else
            break;
    }

    return true;
}

void rsaCrypt::Print_n_phi_e()
{
    gmp_printf("n: %Zd\nphi: %Zd\ne: %Zd\n", n, phi, e);
}


void rsaCrypt::PrintPublicKey()
{
    // gmp_printf("Public Key: ( n: %Zd | e: %Zd )\n", n, e);

    printf("Public key (hex):  ( n: %s | e: %s )\n", mpz_get_str(NULL, 16, n), mpz_get_str(NULL, 16, e));
}

void rsaCrypt::PrintPrivateKey()
{
    printf("Private key (hex):  ( n: %s | d: %s )\n", mpz_get_str(NULL, 16, n), mpz_get_str(NULL, 16, d));
}

void rsaCrypt::rsaCleanup()
{
    mpz_clear(lowerBound);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);
}
// write to text file, read from text file
bool rsaCrypt::WritePublicKeyToFile(string& filepath)
{
    ofstream out;
    out.open(filepath.c_str(), ios::out);

    if(out.good())
    {
        out << "public " << this->getBitNum() << " "
            << "(  n=" << mpz_get_str(NULL, 10, n)
            << "  |  e=" << mpz_get_str(NULL, 10, e) << "  )";
        return true;
    }
    else
    {
        cout << "cannot write to file " << filepath << endl;
        return false;
    }
}

bool rsaCrypt::WritePrivateKeyToFile(string& filepath)
{
    ofstream out;
    out.open(filepath.c_str(), ios::out);

    if(out.good())
    {
        out << "private " << this->getBitNum() << " "
            << "(  n=" << mpz_get_str(NULL, 10, n)
            << "  |  d=" << mpz_get_str(NULL, 10, d) << "  )";
        return true;
    }
    else
    {
        cout << "cannot write to file " << filepath << endl;
        return false;
    }
}


void rsaCrypt::rsaEncryptBlock(std::vector<unsigned char>& source_block, std::vector<unsigned char>& target_block, unsigned int blocksize)
{
    while(source_block.size() % blocksize)
        source_block.push_back(' ');

//    for(int i=0; i<source_block.size(); ++i)
//        cout << source_block[i];
//    cout << endl;

    string source_str_bin;
    for(unsigned int i = 0; i < blocksize; i++)
    {
        string append_byte_bin;
        convertToBinaryNotation(source_block[i], append_byte_bin);
        // fill up with 0 until string comprises 8 digits
        while(append_byte_bin.length() < 8)
            append_byte_bin = "0" + append_byte_bin;

        source_str_bin += append_byte_bin;
    }

    string encryptednum;
    rsaEncryptNum(source_str_bin, encryptednum);
    copy(encryptednum.begin(), encryptednum.end(), back_inserter(target_block));
}

void rsaCrypt::rsaEncryptNum(string& numbuf_bin, string& encryptednum)
{
    mpz_t num_to_encrypt;
    mpz_init_set_str(num_to_encrypt, numbuf_bin.c_str(), 2);

    mpz_t cipher_num; mpz_init(cipher_num);
    mpz_powm(cipher_num, num_to_encrypt, e, n);

    encryptednum = mpz_get_str(NULL, 10, cipher_num);
}

unsigned int rsaCrypt::EncryptFile(std::string& filepath, std::string& targetpath, unsigned int chunksize)
{
    // block to allocate chunks
    char* memblock;
    // Number of chunks
    int chunks;
    ifstream file( filepath.c_str(), ios::in | ios::binary );
    ofstream new_file( targetpath.c_str(), ios::out );

    // check if file exists, if not return 0
    if(!file.good())
    {
        cerr << "source file \"" << filepath << "\" not found" << endl;
        exit(1);
    }

    // get size of source file
    file.seekg(0, ios::end);
    int size = file.tellg();
    // get number of chunks and rest of bytes for lastchunksize
    chunks = (int) size / chunksize;
    int lastchunksize=0;
    lastchunksize = size % chunksize;

    // set read pointer to the beginning of the file
    file.seekg(0, ios::beg);

    // allocate array with the size of the chunks
    // read and write until the last one
    memblock = new char[chunksize];
    for(int i = 0; i < chunks; i++)
    {
        file.read(memblock, chunksize);
        vector<unsigned char> source_block;
        vector<unsigned char> target_block;
        // convert signed to unsigned char
        source_block.assign(memblock, memblock + chunksize);

        rsaEncryptBlock(source_block, target_block, chunksize);
        // add a space between blocks
        target_block.push_back(' ');
        // write target_block to cipher file (stream, delimiter)
        copy(target_block.begin(), target_block.end(), ostream_iterator<unsigned char>(new_file, ""));
    }
    delete[] memblock;

    memblock = new char[lastchunksize];
    if(lastchunksize>0)
    {
        file.read(memblock, lastchunksize);
        vector<unsigned char> source_block;
        vector<unsigned char> target_block;
        // convert signed to unsigned char
        source_block.assign(memblock, memblock + lastchunksize);

        rsaEncryptBlock(source_block, target_block, chunksize);
        // add a space between blocks
        target_block.push_back(' ');
        // write target_block to cipher file (stream, delimiter)
        copy(target_block.begin(), target_block.end(), ostream_iterator<unsigned char>(new_file, ""));
    }

    delete[] memblock;
    file.close();
    new_file.close();
    return size;
}

unsigned int rsaCrypt::DecryptFile(std::string& filepath, std::string& targetpath, unsigned int chunksize)
{
    ifstream file    (filepath.c_str(),  ios::in );
    ofstream new_file(targetpath.c_str(), ios::out | ios::binary);

    // check if file exists, if not return 0
    if(!file.good())
        return 0;

    char* memblock = new char[chunksize];
    unsigned int total = 0;
    while(!file.eof())
    {
        string readnumber = "";
        file >> readnumber;
        if(readnumber.length()>0)
        {
//            cout << "--------readnumber:" << readnumber  << "|" << endl;
            // send memblock through decryption stages
            // size of memblock must be equal to block
            vector<unsigned char> target_block;
            rsaDecryptBlock(readnumber, target_block, chunksize);
            // todo write vector tightly packed to binary file
//            copy(target_block.begin(), target_block.end(), memblock);
            vector<char> memvec;
            memvec.assign(target_block.begin(), target_block.end());
            new_file.write(&memvec[0], chunksize);
            total += chunksize;
        }
    }
    file.close();
    new_file.close();
    delete[] memblock;
    return total;
}

void rsaCrypt::rsaDecryptBlock(std::string& readnumber, std::vector<unsigned char>& target_block, unsigned int chunksize)
{
    // -- take whole number, decrypt it and transform it to binary (rsaDecryptNum())
    // take decry_num_bin, split it to chunks of 8 (byte_str_bin)
    // for each byte_str_bin:
    //     convert to byte_dec, append to target_block

    string decry_num_bin;
    rsaDecryptNum(readnumber, decry_num_bin);

    while(decry_num_bin.length() < chunksize*8)
        decry_num_bin = "0" + decry_num_bin;

    for(unsigned int i=0; i<chunksize; ++i)
    {
        string byte_str_bin = decry_num_bin.substr(i*8, 8);
        unsigned char byte_dec = (unsigned char) convertBinaryToDecimal(byte_str_bin);
        target_block.push_back(byte_dec);
    }
}

void rsaCrypt::rsaDecryptNum(std::string& source_dec, std::string& target_bin)
{
    mpz_t C, K;
    mpz_init(K);
    mpz_init_set_str(C, source_dec.c_str(), 10);
    // gmp_printf("\nC: %Zd, d: %Zd, n: %Zd\n", C, d, n);
    mpz_powm(K, C, d, n);
    // gmp_printf("%Zd ", K);
    target_bin = mpz_get_str(NULL, 2, K);
}



#include <iostream>
#include <stdio.h>
#include <cstdlib>
#include <string>

#include "tools.h"
#include "rsa_class.h"
using namespace std;


int main(int argc, char* argv[])
{
//    while(1)
//
        cout << "/////////////////////////////////////////////////////////" << endl;
        cout << "RSA Encryption Program" << endl;
//             << "enter blocksize (256-blocks(2048 bit) for sufficient security): " << endl;
        unsigned int blocksize = 10;
        rsaCrypt *rsaobj = new rsaCrypt(blocksize*8);

        cout << endl;
        cout << rsaobj->getBitNum() << " Bit RSA Encryption"<< endl;

        rsaobj->rsaGenPrimes()

        while(1)
        {
            if(!rsaobj->rsaGenKeys())
            {
                cout << "some error occured while executing rsaGenKeys(), restart by hitting [RETURN]" << endl;
                rsaobj->rsaCleanup();
                getchar();
                continue;
            }
            break;


        string pub_key_path = "pub_key.txt";
        rsaobj->WritePublicKeyToFile(pub_key_path);
        string priv_key_path = "priv_key.txt";
        rsaobj->WritePrivateKeyToFile(priv_key_path)
        // todo: do it for unsigned char instead of char, so binary files are translated correctl
        string toencrypt_path = "toencrypt_.pdf", cipher_path = "cipher.txt"
        rsaobj->EncryptFile(toencrypt_path, cipher_path, blocksize)
        cout << "encryption done" << endl
        getchar()
        string recreated_path = "recreated.pdf"
        rsaobj->DecryptFile(cipher_path, recreated_path, blocksize)
        cout << "decryption done" << endl
        rsaobj->rsaCleanup();
        delete rsaobj;
        cout << "done" << endl
//        getchar();
//    }

    return 0;
}

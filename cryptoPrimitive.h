/// \file CryptoUtil.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief  definiton the cryptic operation involved in secret sharing
/// \version 0.1
/// \date 2019-03-14
///
/// \copyright Copyright (c) 2019
///

#ifndef SSLIB_CRYPTOUTIL_H
#define SSLIB_CRYPTOUTIL_H

#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "AESRand.h"
/**For Openssl */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
//#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
/**macro for OpenSSL debug */
#define OPENSSL_DEBUG 0
#define OPENSSL_VERSION_1_1 0
/**for the use of mutex lock*/
#include <pthread.h>

/*macro for the type of a high secure pair of hash generation and encryption*/
#define HIGH_SEC_PAIR_TYPE 0
/*macro for the type of a low secure pair of hash generation and encryption*/
#define LOW_SEC_PAIR_TYPE 1
/*macro for the type of a SHA-256 hash generation*/
#define SHA256_TYPE 2
/*macro for the type of a SHA-1 hash generation*/
#define SHA1_TYPE 3
#define hashSize_ 32

/*use /dev/random to generate random data*/
#define RANDOM_SOURCE "/dev/random"

using namespace std;

typedef struct
{
    pthread_mutex_t *lockList;
    long *cntList;
} opensslLock_t;

class CryptoPrimitive
{
private:
    /* data */

    int blockSize_; /// the size of the encryption block
    int keySize_;   /// the size of the key

    int cryptoType_; /// the type of crypto method

    /*variables used in hash generation*/

    const EVP_MD *md_;

    EVP_CIPHER_CTX *decipherctx_ = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *cipherctx_ = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *mdctx_ = EVP_MD_CTX_new();

    const EVP_CIPHER *cipher_;
    unsigned char *iv_;

    static opensslLock_t *opensslLock_; /// OpenSSL Lock

    static void opensslLockingCallback_(int mode, int type, const char *file, int line);

    static void opensslThreadID_(CRYPTO_THREADID *id);

    string randomSource = "/dev/urandom";
    int randFd_;

public:
    /// \brief Construct a new Crypto Util object
    ///
    /// \param cryptoType the type of crypto
    CryptoPrimitive(int cryptoType = HIGH_SEC_PAIR_TYPE);

    /// \brief Destroy the Crypto Util object
    ///
    ~CryptoPrimitive();

    /// \brief set up OpenSSL locks
    ///
    /// \return true succeeds
    /// \return false fails
    static bool opensslLockSetup();

    /// \brief clean up OpenSSL locks
    ///
    /// \return true succeeds
    /// \return false fails

    static bool opensslLockCleanup();

    /// \brief Get the Hash Size object
    ///
    /// \return int the hash size
    int getHashSize();

    /// \brief Get the Key Size object
    ///
    /// \return int the key size
    int getKeySize();

    /// \brief Get the Block Size object
    ///
    /// \return int the block size
    int getBlockSize();

    /// \brief generate the hash for the data stored in a buffer
    ///
    /// \param dataBuffer the buffer that stores the data
    /// \param dataSize the size of data
    /// \param hash the generated hash <return>
    /// \return true generation succeeds
    /// \return false generation fails
    bool generateHash(unsigned char *dataBuffer, const int &dataSize, unsigned char *hash);

    /// \brief generate random data
    ///
    /// \param randomSize the generated random's size
    /// \param random the generated random <return>
    /// \return true generation succeeds
    /// \return false generation fails
    bool generateRandom(int randomSize, unsigned char *random);

    /// \brief  encrypt the data stored in a buffer with a key
    ///
    /// \param dataBuffer the buffer that stored the data
    /// \param dataSize the size of the data
    /// \param key the key used to encrypt the data
    /// \param cipherText the generated cipher text <return>
    /// \return true encryption succeeds
    /// \return false encryption fails
    bool encryptWithKey(unsigned char *dataBuffer, const int &dataSize, unsigned char *key,
                        unsigned char *cipherText);

    bool decryptWithKey(unsigned char *dataBuffer, const int &dataSize, unsigned char *key,
                        unsigned char *plainText);
};
#endif

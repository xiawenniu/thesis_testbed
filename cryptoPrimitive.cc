/// \file CryptoPrimitive.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement interfaces defined in CryptoPrimitive.h
/// \version 0.1
/// \date 2019-03-15
///
/// \copyright Copyright (c) 2019
///

#include "cryptoPrimitive.h"

/**initialize the static variable */
opensslLock_t* CryptoPrimitive::opensslLock_ = NULL;

void CryptoPrimitive::opensslLockingCallback_(int mode, int type, const char* file, int line)
{
#if OPENSSL_DEBUG
    CRYPTO_THREADID id;
    CRYPTO_THREADID_current(&id);
    printf("thread=%4ld, mode=%s, lock=%s, %s:%d\n", id.val, (mode & CRYPTO_LOCK) ? "l" : "u", (type & CRYPTO_READ) ? "r" : "w", file, line);
#endif

    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(opensslLock_->lockList[type]));
        CryptoPrimitive::opensslLock_->cntList[type]++;
    } else {
        pthread_mutex_unlock(&(opensslLock_->lockList[type]));
    }
}

/// \brief get the id of the current thread
///
/// \param id the return id <return>

void CryptoPrimitive::opensslThreadID_(CRYPTO_THREADID* id)
{
    CRYPTO_THREADID_set_numeric(id, pthread_self());
}

/// \brief set up OpenSSL locks
///
/// \return true succeeds
/// \return false fails

bool CryptoPrimitive::opensslLockSetup()
{
#if defined(OPENSSL_THREADS)
    //printf("OpenSSL lock setup started\n");

    opensslLock_ = (opensslLock_t*)malloc(sizeof(opensslLock_t));

    opensslLock_->lockList = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    opensslLock_->cntList = (long*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    //printf("cntList[i]:CRYPTO_get_lock_name(i)\n");
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(opensslLock_->lockList[i]), NULL);
        opensslLock_->cntList[i] = 0;
        //printf("%8ld\n", opensslLock_->cntList[i]);
    }

    CRYPTO_THREADID_set_callback(&opensslThreadID_);
    CRYPTO_set_locking_callback(&opensslLockingCallback_);

    printf("OpenSSL lock setup done\n");

    return true;
#else
    printf("Error: OpenSSL was not configured with thread support!\n");

    return 0;
#endif
}
/// \brief clean up OpenSSL locks
///
/// \return true succeeds
/// \return false fails
bool CryptoPrimitive::opensslLockCleanup()
{
#if defined(OPENSSL_THREADS)
    CRYPTO_set_locking_callback(NULL);

    printf("OpenSSL lock cleanup started\n");

    printf("cntList[i]:CRYPTO_get_lock_name(i)\n");
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(opensslLock_->lockList[i]));
        //printf("%8ld:%s\n", opensslLock_->cntList[i], CRYPTO_get_lock_name(i));
    }

    OPENSSL_free(opensslLock_->lockList);
    OPENSSL_free(opensslLock_->cntList);
    free(opensslLock_);

    printf("OpenSSL lock cleanup done\n");

    return 1;
#else
    printf("Error: OpenSSL was not configured with thread support!\n");

    return 0;
#endif
}

/// \brief Construct a new Crypto Util:: Crypto Util object
///
/// \param cryptoType the type of CryptoPrimitive

CryptoPrimitive::CryptoPrimitive(int cryptoType)
{
    if (!CryptoPrimitive::opensslLockSetup()) {
        printf("fail to set up OpenSSL locks\n");
        exit(1);
    }
    cryptoType_ = cryptoType;

#if defined(OPENSSL_THREADS)
    /**check if opensslLockSetup() has been called to set up OpenSSL locks */
    if (opensslLock_ == NULL) {
        printf("Error: opensslLockSetup() was not called before initializing CryptoPrimitive instances\n");
        exit(1);
    }

    if (cryptoType_ == HIGH_SEC_PAIR_TYPE) {
       
        /**get the MVP_MD structure for SHA-256 */
        md_ = EVP_sha256();

        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(mdctx_);
        cerr<<mdctx_<<endl;
        /**initializes decipher context decipherctx_ */
        EVP_CIPHER_CTX_init(decipherctx_);

        /**initializes cipher context cipherctx_*/
        EVP_CIPHER_CTX_init(cipherctx_);
        cerr<<hashSize_<<endl;

        /**get the EVP_CIPHER structure for AES-256 */
        cipher_ = EVP_aes_256_cbc();
        keySize_ = 32;
        blockSize_ = 16;

        /**allocate a constant IV*/
        iv_ = (unsigned char*)malloc(sizeof(unsigned char) * blockSize_);
        memset(iv_, 0, blockSize_);

        /*printf("\nA CryptoPrimitive based on a pair of SHA-256 and AES-256 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("      keySize_: %d \n", keySize_);
        printf("      blockSize_: %d \n", blockSize_);
        printf("\n");*/
    }

    if (cryptoType == LOW_SEC_PAIR_TYPE) {
        
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(mdctx_);

        /**get the EVP_MD structure for MD5 */
        md_ = EVP_md5();


        /**get the EVP_CIPHER stucture for AES-128 */
        cipher_ = EVP_aes_128_cbc();
        keySize_ = 16;
        blockSize_ = 16;

        /**allocate a constant IV */
        iv_ = (unsigned char*)malloc(sizeof(unsigned char) * blockSize_);
        memset(iv_, 0, blockSize_);

        printf("\nA CryptoPrimitive based on a pair of MD5 and AES-128 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("      keySize_: %d \n", keySize_);
        printf("      blockSize_: %d \n", blockSize_);
        printf("\n");
    }

    if (cryptoType_ == SHA256_TYPE) {
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(mdctx_);
        /**get the EVP_MD structure for SHA-256 */
        md_ = EVP_sha256();

        keySize_ = -1;
        blockSize_ = -1;

        printf("\nA CryptoPrimitive based on SHA-256 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("\n");
    }

    if (cryptoType_ == SHA1_TYPE) {

        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_init(mdctx_);

        /**get the EVP_MD structure for SHA-1 */
        md_ = EVP_sha1();

        keySize_ = -1;
        blockSize_ = -1;

        printf("\nA CryptoPrimitive based on SHA-1 has been constructed! \n");
        printf("Parameters: \n");
        printf("      hashSize_: %d \n", hashSize_);
        printf("\n");
    }

#else
    printf("Error: OpenSSL was not configured with thread support!\n");
    exit(1);
#endif

    randFd_ = open(randomSource.c_str(),O_RDONLY);
}

/// \brief Destroy the Crypto Util:: Crypto Util object
///
CryptoPrimitive::~CryptoPrimitive()
{
    if ((cryptoType_ == HIGH_SEC_PAIR_TYPE) || (cryptoType_ == LOW_SEC_PAIR_TYPE)) {
        /**clean up the digest context mdctx_ and free up the space allocated to it */
        EVP_MD_CTX_reset(mdctx_);
        EVP_CIPHER_CTX_reset(cipherctx_);
        EVP_CIPHER_CTX_reset(decipherctx_);
        free(iv_);
    }

    if ((cryptoType_ == SHA256_TYPE) || (cryptoType_ == SHA1_TYPE)) {
        /**clean up the digest context mdctx_ and free up the space allocated to it */
        /**allocate, initialize and return the digest context mdctx_ */
        EVP_MD_CTX_reset(mdctx_);
        
    }
    close(randFd_);
    printf("\nThe CryptoPrimitive has been destructed! \n");
    printf("\n");
}

/// \brief get the hash size
///
/// \return int the hash size
int CryptoPrimitive::getHashSize()
{
    return hashSize_;
}

/// \brief get the key size
///
/// \return int the key size
int CryptoPrimitive::getKeySize()
{
    return keySize_;
}

/// \brief get the size of encryption block unit
///
/// \return int the block size
int CryptoPrimitive::getBlockSize()
{
    return blockSize_;
}

bool CryptoPrimitive::decryptWithKey(unsigned char* dataBuffer, const int& dataSize, unsigned char* key,
    unsigned char* plainText) {
    int plainTextSize, plainTextTailSize;

    if (dataSize % blockSize_ != 0) {
        printf("Error: the size of the input data (%d bytes) is not a multiple of that of encryption block unit (%d bytes)!\n",
            dataSize, blockSize_);
        return false;
    }

    EVP_DecryptInit_ex(decipherctx_, cipher_, NULL, key, iv_);
    /*disable padding to ensure that the generated ciphertext has the same size as the input data*/

    /**start to decrypt */
    EVP_CIPHER_CTX_set_padding(decipherctx_, 0);
    EVP_DecryptUpdate(decipherctx_, plainText, &plainTextSize, dataBuffer, dataSize);
    EVP_DecryptFinal_ex(decipherctx_, plainText + plainTextSize, &plainTextTailSize);
    //TODO: this pary may be replaced by new library

    plainText += plainTextTailSize;

    if (plainTextSize != dataSize) {
        printf("Error: the size of the plaintext output (%d bytes) does not match with that of the input (%d bytes)!\n",
            plainTextSize, dataSize);
        return false;
    }

    return true;
}

/// \brief encrypt the data stored in a buffer with a key
///
/// \param dataBuffer the buffer storing the data
/// \param dataSize the size of the data
/// \param key the key used to encrypt the data
/// \param cipherText the generated ciphertext <return>
/// \return true encryption succeeds
/// \return false encryption fails

bool CryptoPrimitive::encryptWithKey(unsigned char* dataBuffer, const int& dataSize, unsigned char* key,
    unsigned char* cipherText)
{
    int cipherTextSize, cipherTextTailSize;

    if (dataSize % blockSize_ != 0) {
        printf("Error: the size of the input data (%d bytes) is not a multiple of that of encryption block unit (%d bytes)!\n",
            dataSize, blockSize_);
        return false;
    }

    //TODO: this part may be replaced by new library
    EVP_EncryptInit_ex(cipherctx_, cipher_, NULL, key, iv_);
    /*disable padding to ensure that the generated ciphertext has the same size as the input data*/
    EVP_CIPHER_CTX_set_padding(cipherctx_, 0);
    EVP_EncryptUpdate(cipherctx_, cipherText, &cipherTextSize, dataBuffer, dataSize);
    EVP_EncryptFinal_ex(cipherctx_, cipherText + cipherTextSize, &cipherTextTailSize);


    cipherTextSize += cipherTextTailSize;

    if (cipherTextSize != dataSize) {
        printf("Error: the size of the cipher output (%d bytes) does not match with that of the input (%d bytes)!\n",
            cipherTextSize, dataSize);
        return false;
    }

    return true;
}

/// \brief generate the hash for the data stored in a buffer
///
/// \param dataBuffer the buffer that stores the data
/// \param dataSize the size of the data
/// \param hash the generated hash <return>
/// \return true generation succeeds
/// \return false generation fails

bool CryptoPrimitive::generateHash(unsigned char* dataBuffer, const int& dataSize, unsigned char* hash)
{
    int hashSize;
    EVP_MD_CTX *mdctx1_ = EVP_MD_CTX_new();
    EVP_MD_CTX_init(mdctx1_);
    const EVP_MD *md_ = EVP_sha256();

    EVP_DigestInit_ex(mdctx1_, md_, NULL);
    EVP_DigestUpdate(mdctx1_, dataBuffer, dataSize);
    EVP_DigestFinal_ex(mdctx1_, hash, (unsigned int*)&hashSize);


    if (hashSize != hashSize_) {
        printf("Error: the size of the generated hash (%d bytes) does not match with the expected one (%d bytes)!\n",
            hashSize, hashSize_);

        return false;
    }
    return true;
}

/// \brief generate random data
///
/// \param randomSize the generated random's size
/// \param random the generated random <return>
/// \return true generation succeeds
/// \return false generation fails
bool CryptoPrimitive::generateRandom(int randomSize, unsigned char* random)
{

    simd128 state = AESRand_init(); 
    AESRand_increment(state);
    int intNumber = randomSize / (sizeof(uint32_t) * 8);
    int endNumber = randomSize - intNumber * (sizeof(uint32_t) * 8);
    int count = 0;
    for(int index = 0; index < intNumber; index++){
	std::array<uint32_t, 8> ints = AESRand_rand_uint32(state);
    	for(int i = 0; i < 8; i++) {
	    memcpy(random + count, (void*)&ints[i], sizeof(uint32_t));
	    count += sizeof(uint32_t);
    	}
    }
    std::array<uint32_t, 8> ints = AESRand_rand_uint32(state);
    memcpy(random + count, (void*)&ints[0], endNumber);
    return true;
	
/*
    if (randFd_ == -1){
	//cerr << "error in read " << randomSource.c_str() << endl;
	return false;
    }
    read(randFd_, random, randomSize);
    return true;
*/
/*    
    int ret = RAND_bytes(random, randomSize);
    if (ret != 1) {
        printf("error random\n");
        return false;
    } else
        return true;
  */  
}

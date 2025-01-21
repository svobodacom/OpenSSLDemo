#ifndef CIPHER_H
#define CIPHER_H

#include <QObject>
#include <QDebug>
#include <QFile>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PADDING RSA_PKCS1_PADDING
#define KEYSIZE 32
#define IVSIZE 32
#define BLOCKSIZE 256
#define SALTSIZE 8

class Cipher : public QObject
{
    Q_OBJECT
public:
    explicit Cipher(QObject *parent = nullptr);

    // loads the public key from a byte array
    RSA *getPublicKey(QByteArray &data);
    // loads the public key from a file
    RSA *getPublicKey(QFile filename);

    RSA *getPrivateKey(QByteArray &data);
    RSA *getPrivateKey(QFile filename);

    // encrypts a byte arrray using the RSA public key
    QByteArray encryptRSA(RSA *key, QByteArray &data);

    // decrypts a byte array using the RSA private key (returned decrypted byte array)
    QByteArray decryptRSA(RSA *key, QByteArray &data);

    // encrypt a byte array with AES 256 CBC
    QByteArray encryptAES(QByteArray passphrase, QByteArray &data);

    // decrypt a byte array with AES 256 CBC
    QByteArray decryptAES(QByteArray passphrase, QByteArray &data);

    // get a byte array filled with random information
    QByteArray randomBytes(int size);

    // frees RSA key from a memory
    void freeRSAKey(RSA *key);

signals:

public slots:

private:
    // initialize the OpenSSL lib
    void initialize();
    // cleanup after the OpenSSL lib
    void finalize();

    // loads a file and returns a byte array
    QByteArray readFile(QString filename);

    // writes a byte array to a file
    void writeFile(QString filename, QByteArray &data);
};

#endif // CIPHER_H

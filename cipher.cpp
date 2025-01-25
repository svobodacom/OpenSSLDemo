#include "cipher.h"

Cipher::Cipher(QObject *parent) : QObject{parent}
{
    initialize();
}

Cipher::~Cipher()
{
    finalize();
}

////////////////////////////////////////////////////////////////////

RSA *Cipher::getPublicKey(QByteArray &data)
{
    const char* publicKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    EVP_PKEY* evpKey = PEM_read_bio_PUBKEY(bio,NULL,NULL,NULL);

    if (!evpKey)
    {
        qCritical() << "Could not load public key" << ERR_error_string(ERR_get_error(), NULL);
    }

    RSA* rsaPubKey = EVP_PKEY_get1_RSA(evpKey);
    if (!rsaPubKey) {
        qCritical() << "Could not extract RSA key" << ERR_error_string(ERR_get_error(), NULL);
    }

    BIO_free(bio);
    EVP_PKEY_free(evpKey);
    return rsaPubKey;
}


RSA *Cipher::getPublicKey(QString filename)
{
    QByteArray data = readFile(filename);

    return getPublicKey(data);
}


RSA *Cipher::getPrivateKey(QByteArray &data)
{

}


RSA *Cipher::getPrivateKey(QString filename)
{

}

////////////////////////////////////////////////////////////////////

QByteArray Cipher::encryptRSA(RSA *key, QByteArray &data)
{

}


QByteArray Cipher::decryptRSA(RSA *key, QByteArray &data)
{

}


QByteArray Cipher::encryptAES(QByteArray passphrase, QByteArray &data)
{

}


QByteArray Cipher::decryptAES(QByteArray passphrase, QByteArray &data)
{

}



QByteArray Cipher::randomBytes(int size)
{

}


void Cipher::freeRSAKey(RSA *key)
{

}

////////////////////////////////////////////////////////////////////

void Cipher::initialize()
{
    OPENSSL_init_crypto(0, NULL);
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}


void Cipher::finalize()
{
    EVP_cleanup();
    ERR_free_strings();
}


QByteArray Cipher::readFile(QString filename)
{
    QByteArray data;
    QFile file(filename);

    if (!file.open(QFile::ReadOnly))
    {
        qCritical() << file.errorString();
        return data;
    }

    data - file.readAll();
    file.close();
    return data;
}


void Cipher::writeFile(QString filename, QByteArray &data)
{

}

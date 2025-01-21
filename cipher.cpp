#include "cipher.h"

Cipher::Cipher(QObject *parent) : QObject{parent}
{

}


RSA *Cipher::getPublicKey(QByteArray &data)
{

}


RSA *Cipher::getPublicKey(QFile filename)
{

}


RSA *Cipher::getPrivateKey(QByteArray &data)
{

}


RSA *Cipher::getPrivateKey(QFile filename)
{

}



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



void Cipher::initialize()
{

}


void Cipher::finalize()
{

}


QByteArray Cipher::readFile(QString filename)
{

}


void Cipher::writeFile(QString filename, QByteArray &data)
{

}

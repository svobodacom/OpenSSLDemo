#include <QCoreApplication>
#include "cipher.h"

QByteArray getPublicKey()
{
    QByteArray testPublicKey;

    testPublicKey.append("-----BEGIN PUBLIC KEY-----\n");
    testPublicKey.append("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAppYlVsDS93KICWJ15AA3\n");
    testPublicKey.append("mY6t2SyyBDtzQ50bDi/bWlo0DYOjpyDsKhSREVVegFoL6y3Jf7NRgMh21pc8yCya\n");
    testPublicKey.append("sjIu7aoMTSahFG1PK3AL2PEaatr2FWY6rYx1s+pv4WfmJQ8m6uVKhk+/SO4DqChw\n");
    testPublicKey.append("OuwjobQzwFGhuWh9l/w0nCNF+x+fSQYZwmJoUpMIeC+CVfn0WXAGY+itx9wnoh/2\n");
    testPublicKey.append("bTiqaZGMyuZuTiop6xKESKhVTbIi+se+oxPY/F7FT6zUMN4dPLonXHrHlRuMs3Pf\n");
    testPublicKey.append("KORKuerSZYRGJO3Gosn2Z7X7635bbz96fE3hpXZUcst+cI9S5UCYIsxEyfeiTzhR\n");
    testPublicKey.append("rQIDAQAB\n");
    testPublicKey.append("-----END PUBLIC KEY-----");

    return testPublicKey;
}

QByteArray getPrivateKey()
{
    QByteArray testPrivateKey;

    testPrivateKey.append("-----BEGIN PRIVATE KEY-----\n");
    testPrivateKey.append("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmliVWwNL3cogJ\n");
    testPrivateKey.append("YnXkADeZjq3ZLLIEO3NDnRsOL9taWjQNg6OnIOwqFJERVV6AWgvrLcl/s1GAyHbW\n");
    testPrivateKey.append("lzzILJqyMi7tqgxNJqEUbU8rcAvY8Rpq2vYVZjqtjHWz6m/hZ+YlDybq5UqGT79I\n");
    testPrivateKey.append("7gOoKHA67COhtDPAUaG5aH2X/DScI0X7H59JBhnCYmhSkwh4L4JV+fRZcAZj6K3H\n");
    testPrivateKey.append("3CeiH/ZtOKppkYzK5m5OKinrEoRIqFVNsiL6x76jE9j8XsVPrNQw3h08uidceseV\n");
    testPrivateKey.append("G4yzc98o5Eq56tJlhEYk7caiyfZntfvrfltvP3p8TeGldlRyy35wj1LlQJgizETJ\n");
    testPrivateKey.append("96JPOFGtAgMBAAECggEAMWPJvT9dLRUtZQ7mogs4cNQfEgkQ3HVd1rmRKHMi51Zg\n");
    testPrivateKey.append("IXOahTYbHtzLJ+b2JjrMVtVT7QMW0oZcyYG8eSLUWKnNRRSKIiOmVV6VPu0w7giJ\n");
    testPrivateKey.append("yw2RMUYGdqbyzL1gn2VFFE66PKFvp4OkVHSQ6/3VTHrvk4VQZKAvQT/MINAbLwFA\n");
    testPrivateKey.append("/ZrUcs5CnsmqOe3dWwXoHfBrcModrlwJY1qS2gpTP0Q5z7fCyH5s7c0QzECoF+tN\n");
    testPrivateKey.append("8KXyr7x1ljtCHoouVs2m+210ZeUjrDD9L5IP5t1vJXTaQMKLsCCX7F+TLrnni3cc\n");
    testPrivateKey.append("R6mXhFwmb3j2h5L3yPfrp/Pspv2LIeCdCmel0GiMRwKBgQDntClstI25MmaY/GM7\n");
    testPrivateKey.append("Xny8FL+/CMBuFUnM2rmN7O2xeIyzRFZXSfpd6bcelKVh8nDPqWSNypupbeakfjD3\n");
    testPrivateKey.append("dnWcNOxf+Fp3QLZRr9oE9vHsu/YZOyXxs8LtOUOWW6t9MI71SdMPAb59CEWQg5HO\n");
    testPrivateKey.append("IBWzIcomZEd8c50lybrwO6zY2wKBgQC4DftDQgfNkQb9JT1jOevcTjKltbFLgLkP\n");
    testPrivateKey.append("nStEWCu5XsqcHMWZ1ECVbqP0rcB7c9zCnEmWFpc4ERJ0cPJ1SraXp5CWhVpqvlO4\n");
    testPrivateKey.append("51PqoU2VBzmLwbpWmLtfKoD2d8K2JUxNQo2AJBHkp+5IY+MY2EwHZrpqOVZOwJXQ\n");
    testPrivateKey.append("5EiTpBdiFwKBgQDHbpnNOCdYRVpryak725svZAiazFSdK/OmwIi/8TOx8pngXyyV\n");
    testPrivateKey.append("21YFaXo1dypWgQ+6ngmvxblv/ulrojZReYPHnQHrpN9xD6Ed9GeKqGcZJbuwgemp\n");
    testPrivateKey.append("/dkEyKo1C9gyXA5gcFea7hxgkDMYLTbdnV4wHiBaJSwmoXicouMljae7ywKBgAjo\n");
    testPrivateKey.append("hFTJCV+luVTfTI1U7FmJX2It3RrubAaZcNKqAdPDBsNvkRDU+RtCc6UQE9Tl0rWI\n");
    testPrivateKey.append("ovckuMT57o68OL/8kcHdVl4yriGkfKDicWlVzU99PgfJpJ80XT1J7VwAh+gQ/hRv\n");
    testPrivateKey.append("ODIPjN4oUpwmWYOGVIe3LSafB9Jf9+BYbDrZIliZAoGAPNtwhMWMcKL4oX/4wg7C\n");
    testPrivateKey.append("LC7tMw7g2scsn3vtHtLoPwroeb1KHKqJkph553lzmxeyXH+Xt5SEzVUVWjLqghlQ\n");
    testPrivateKey.append("6/zfji6EULUT1mNJqFJEato2KpgqGtYFNzVE64tdZgKoFwzD7v0O/Lq5nObOVSQJ\n");
    testPrivateKey.append("ljHzGMeyJIFi36+JdJ2UU+4=\n");
    testPrivateKey.append("-----END PRIVATE KEY-----");

    return testPrivateKey;
}

void testRSA()
{
    qDebug() << "Loading keys...";
    QByteArray testPrivateKey = getPrivateKey();
    QByteArray testPublicKey = getPublicKey();

    Cipher cWrapper;

    RSA* publickey = cWrapper.getPublicKey(testPublicKey);
    RSA* privatekey = cWrapper.getPrivateKey(testPrivateKey);

    QByteArray plain = "The man in black go into the forest and died";
    QByteArray encrypted = cWrapper.encryptRSA(publickey, plain);
    QByteArray decrypted = cWrapper.decryptRSA(privatekey, encrypted);

    qDebug() << plain << "\n";
    qDebug() << encrypted.toBase64();
    qDebug() << "\n" << decrypted;

    cWrapper.freeRSAKey(publickey);
    cWrapper.freeRSAKey(privatekey);
}

void testAES()
{
    qDebug() << "Testing AES...";

    Cipher cWrapper;
    QString passphrase = "MyPassword";
    QByteArray plain = "Soon the war should stop! Dont waste your money!!!";

    QByteArray encrypted = cWrapper.encryptAES(passphrase.toLatin1(), plain);
    QByteArray decrypted = cWrapper.decryptAES(passphrase.toLatin1(), encrypted);

    qDebug() << plain << "\n";
    qDebug() << encrypted.toBase64();
    qDebug() << "\n" << decrypted;
}


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    testAES();
    //testRSA();

    return a.exec();
}

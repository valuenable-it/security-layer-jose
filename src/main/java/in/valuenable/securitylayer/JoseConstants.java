package in.valuenable.securitylayer;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class JoseConstants {
public static final String KEY_INSTANCE_AES = "AES";

//PEM formatted key
static final String SOURCE_PUBLIC_KEY_RAW = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouixtNlvsZoC3mEZBIO0
YAZ4Ypm+YKa1P+LCAXorYr9llidY/O7jtIrR53xXvtjrHtc97NrDsLwri3T0Y91o
CdVvWxmGwgTZdO19VIiaSUJybpxXG98vEtf0uPNbIa/7kcsVHqRdivmcT6d75rQ9
0P1lHAka1cABmfXTplneUpdysqo2Efy8yWhUSlHvEjnMmAnNb72EZp4wPdcCfaTI
AYzeJDU3kRNVZCAh83SI4XdpB+HcZHkYCrH5KpHnBRR74eVsScNSesPU/Q6CRcXE
IW5NhrvceEt6vShzaHfbIijVUz87JDFqIhwME3u0yR2tiN41+/MwPWjY4RqcUz2c
WwIDAQAB
-----END PUBLIC KEY-----
        """;
static final String SOURCE_PRIVATE_KEY_RAW = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCi6LG02W+xmgLe
YRkEg7RgBnhimb5gprU/4sIBeitiv2WWJ1j87uO0itHnfFe+2Ose1z3s2sOwvCuL
dPRj3WgJ1W9bGYbCBNl07X1UiJpJQnJunFcb3y8S1/S481shr/uRyxUepF2K+ZxP
p3vmtD3Q/WUcCRrVwAGZ9dOmWd5Sl3KyqjYR/LzJaFRKUe8SOcyYCc1vvYRmnjA9
1wJ9pMgBjN4kNTeRE1VkICHzdIjhd2kH4dxkeRgKsfkqkecFFHvh5WxJw1J6w9T9
DoJFxcQhbk2Gu9x4S3q9KHNod9siKNVTPzskMWoiHAwTe7TJHa2I3jX78zA9aNjh
GpxTPZxbAgMBAAECggEAB8648y7Q+UUlNwz82ttvC4OAq7hF+5hxxLta5FQ7fEX2
meqOPsA6N7hheynzHWmElzVMn/hG4a0BaNnn+1msnbAJE4FWyB/dLIsg2Xc0iCdM
y0iBE9jJIKrEU6rbs4xQgiCM0hIH86jaP3Nw7wUbY1OjNjB160gCkgmwi5JW1kSd
ShBCcQveI9LbPkAl4iyfAL5PgeG355WEWa7Ke1zHWCFo/HXBGzvj1mcIm7z8Tdej
uQQypmK11gxOLCBo6kXyq0lCoi0eK3t5sgR37k9YygiG8Sh/B5ib3ayUCtjxX89g
5xS9qwsVKxyRL3xvej0hVZAK+TbZlYmQjSUDIeYHVQKBgQDQ+Df0wq+CrMXnWSln
0Fg+Q6rgJS4VxGzGa0/7LNM6AAPr0BQgvA5Esh0ofWL2eNkG1VlgTKbk8pj5tWaL
yuI0G6WSdSQrJQ4WPWTMTRF10Zc5MRZaPF7lhzrDfDmQ730V2LK88OBStFJ6Q44G
FOmgQ1LkhSJfwXD4kYUrvO6QxwKBgQDHkrEzhMKexYexzBDjl8d1t8YI/tsm1dls
88MPY3ZI1wBE3QOciMvb5ZcstsrhAIARA3hl+U8KG8c/FAAMl6dFBmAZ14LNZt8L
sLWr/zwV7Zm5aI+PclvAQ112VD7LHE0xT/NZQWFkQZehqzd9C3qD75DuVS0xUEcG
5Q0XaUvrzQKBgDSKlJcn9DUo98GJe42spuNQ5D/jWUkD0E27YarHxHxK0LGT6dup
LPU8y3QIwr8x929uaUB7RWM/VBNE9vmjE2kCoojGh0eJ05bn7NYpcoBrKFiq7PHX
SAzyCWZpb5fvf0Xk7FvxPJXO3QX8wlLpIyy2gLsQdmoZGyyEejVbFai1AoGBAIkZ
B6wpjnz9m0sTsaJ3mOkQVvXFBg22qIeFKUHABPji4edsoNd+zfSA0wo/hD1vV4rY
hHQhASAjlwuJFMORxrHPQGNgPhYWjjD8ssC2NLOnpovM/ZoAaHE6ldD87KohBhJT
JwvwsxPpT14bPaIkKYTLJRfk4YfX6wMchJLJngMdAoGBALhLUxKJF+cHDdqE65zC
fezp5audRR0F+2jSkEkporPNs+L4AdXV53QOdfvH6QT51CrRq16mBZvBaThOhEAc
3Pdq5s5kmnoQmdUxrFFYbu2FI24PmHy6INamtTLuqIlIJ/HSD8KYpTAdnqlbfchZ
O7lth0WGUaBbUCoLDGVsKeMO
-----END PRIVATE KEY-----
        """;
static final String DESTINATION_PUBLIC_KEY_RAW = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouixtNlvsZoC3mEZBIO0
YAZ4Ypm+YKa1P+LCAXorYr9llidY/O7jtIrR53xXvtjrHtc97NrDsLwri3T0Y91o
CdVvWxmGwgTZdO19VIiaSUJybpxXG98vEtf0uPNbIa/7kcsVHqRdivmcT6d75rQ9
0P1lHAka1cABmfXTplneUpdysqo2Efy8yWhUSlHvEjnMmAnNb72EZp4wPdcCfaTI
AYzeJDU3kRNVZCAh83SI4XdpB+HcZHkYCrH5KpHnBRR74eVsScNSesPU/Q6CRcXE
IW5NhrvceEt6vShzaHfbIijVUz87JDFqIhwME3u0yR2tiN41+/MwPWjY4RqcUz2c
WwIDAQAB
-----END PUBLIC KEY-----
        """;

public static final RSAPublicKey PUBLIC_KEY() throws Exception {

    // Remove the first and last lines of the PEM string
    String keyPEMBody = SOURCE_PUBLIC_KEY_RAW.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

    // Remove any newline characters in the PEM body
    keyPEMBody = keyPEMBody.replaceAll("\\s", "");

    // Decode the Base64-encoded bytes
    byte[] keyBytes = Base64.getDecoder().decode(keyPEMBody);

    // Create a key specification object from the key bytes
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

    // Create the public key
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey =  keyFactory.generatePublic(keySpec);

    return (RSAPublicKey)publicKey;
}
public static final RSAPrivateKey PRIVATE_KEY () throws Exception {

    // Remove the first and last lines of the PEM string
    String keyPEMBody = SOURCE_PRIVATE_KEY_RAW.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

    // Remove any newline characters in the PEM body
    keyPEMBody = keyPEMBody.replaceAll("\\s", "");
    // Decode the Base64-encoded bytes
    byte[] keyBytes = Base64.getDecoder().decode(keyPEMBody);

    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

    // Create the public key
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PrivateKey privateKey =  keyFactory.generatePrivate(keySpec);

    return (RSAPrivateKey)privateKey;
}

public static final RSAPublicKey DESTINATION_PUBLIC_KEY () throws Exception {

    // Remove the first and last lines of the PEM string
    String keyPEMBody = DESTINATION_PUBLIC_KEY_RAW.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

    // Remove any newline characters in the PEM body
    keyPEMBody = keyPEMBody.replaceAll("\\s", "");
    // Decode the Base64-encoded bytes
    byte[] keyBytes = Base64.getDecoder().decode(keyPEMBody);

    // Create a key specification object from the key bytes
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

    // Create the public key
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey =  keyFactory.generatePublic(keySpec);

    return (RSAPublicKey)publicKey;
}

private JoseConstants() {

}
}
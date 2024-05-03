#include "generate-key.hpp"
#include <iostream>
#include <stdexcept>

using namespace CryptoPP;

ecdsa256::KeyPair GenerateKey()
{
    //std::cout << "Generating key..." << std::endl;

    AutoSeededRandomPool rng;
    OID oid(CryptoPP::ASN1::secp256r1());
    ECDSA<ECP, SHA256>::PrivateKey private_key;
    private_key.Initialize(rng, oid);

    if (!private_key.Validate(rng, 3)) {
        throw std::runtime_error("Private key validation failed");
    }

    ecdsa256::KeyPair key_pair;

    auto& private_exponent = private_key.GetPrivateExponent();
    private_exponent.Encode(key_pair.private_key.key.data(), key_pair.private_key.key.size());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey public_key;
    private_key.MakePublicKey(public_key);

    auto& public_element = public_key.GetPublicElement();
    public_element.x.Encode(key_pair.public_key.x.data(), key_pair.public_key.x.size());
    public_element.y.Encode(key_pair.public_key.y.data(), key_pair.public_key.y.size());

    return key_pair;
}

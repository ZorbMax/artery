// PseudonymMessage.msg

cplusplus {{
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signature.hpp>
#include <vector>
}}

// Declare external classes with @existingClass
class vanetza::security::HashedId8
{
    @existingClass;
}

class vanetza::security::EcdsaSignature
{
    @existingClass;
}

class vanetza::security::Certificate
{
    @existingClass;
}

class vanetza::security::ecdsa256::PublicKey
{
    @existingClass;
}

packet PseudonymMessage
{
    simtime_t timestamp;                      // Timestamp of the message
    vanetza::security::Certificate certificate;  // Certificate of the sender
    vanetza::security::Certificate pseudonym;  // Generated pseudonym
    vanetza::security::ecdsa256::PublicKey public_key; // Public Key to be used in the pseudonym
    vanetza::security::EcdsaSignature signature; // Signature of the message
    string payload;                            // Payload of the message
}

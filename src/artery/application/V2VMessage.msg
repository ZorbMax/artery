cplusplus {{
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signature.hpp>
#include <string>
}}

// Declare external classes with @existingClass
class vanetza::security::EcdsaSignature
{
    @existingClass;
}

class vanetza::security::Certificate
{
    @existingClass;
}

packet V2VMessage
{
    simtime_t timestamp;                      // Timestamp of the message
    vanetza::security::Certificate certificate;  // Certificate of the sender
    vanetza::security::EcdsaSignature signature; // Signature of the message
    string payload;                            // Payload of the message
}

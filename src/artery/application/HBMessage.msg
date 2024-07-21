// HBMessage.msg

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

packet HBMessage
{
    simtime_t mTimestamp;
    vanetza::security::HashedId8 mRevokedCertificates[];
    vanetza::security::EcdsaSignature mSignature;
    vanetza::security::Certificate mSignerCertificate;
}

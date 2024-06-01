// CRLMessage.msg

cplusplus {{
#include <vector>
#include "vanetza/security/HashedId8.h"
#include "vanetza/security/EcdsaSignature.h"
#include "vanetza/security/Certificate.h"
}}

// Declare external classes with the @existingClass property
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

packet CRLMessage
{
    simtime_t mTimestamp;
    vanetza::security::HashedId8 mRevokedCertificates[]; // Array of HashedId8
    vanetza::security::EcdsaSignature mSignature;
    vanetza::security::Certificate mSignerCertificate;
}

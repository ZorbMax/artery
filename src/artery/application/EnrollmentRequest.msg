cplusplus {{
#include <vanetza/security/basic_elements.hpp>
#include <string>
}}

class vanetza::security::ecdsa256::PublicKey
{
    @existingClass;
}

packet EnrollmentRequest
{
    string vehicleId;
    vanetza::security::ecdsa256::PublicKey publicKey;
}

#ifndef GENERATE_CERTIFICATE_HPP
#define GENERATE_CERTIFICATE_HPP

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>

namespace vanetza
{
namespace security
{

Certificate GenerateCertificate(const HashedId8& root_hash, ecdsa256::PrivateKey& root_key, ecdsa256::PublicKey& key);

Certificate GeneratePseudonym(const HashedId8& root_hash, ecdsa256::PrivateKey& root_key, ecdsa256::PublicKey& key);

}  // namespace security
}  // namespace vanetza

#endif  // GENERATE_CERTIFICATE_HPP

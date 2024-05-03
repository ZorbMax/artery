#include "generate-root.hpp"
#include <boost/program_options.hpp>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>

namespace aid = vanetza::aid;
namespace po = boost::program_options;
using namespace vanetza::security;

Certificate GenerateRoot(ecdsa256::KeyPair key)
{
    BackendCryptoPP crypto_backend;
    std::string subject_name = "Hello World Root-CA";
    int validity_days = 365;

    // Retrieving keys
    ecdsa256::KeyPair subject_key = key;

    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());

    // create certificate
    Certificate certificate;
    std::list<IntX> certificate_aids;
    certificate_aids.push_back(IntX(aid::CA));
    certificate_aids.push_back(IntX(aid::DEN));

    certificate.subject_attributes.push_back(certificate_aids);

    // section 6.1 in TS 103 097 v1.2.1
    certificate.signer_info = nullptr; /* self */

    // section 6.3 in TS 103 097 v1.2.1
    certificate.subject_info.subject_type = SubjectType::Root_CA;

    // section 7.4.2 in TS 103 097 v1.2.1
    std::vector<unsigned char> subject(subject_name.begin(), subject_name.end());
    certificate.subject_info.subject_name = subject;

    // section 6.6 in TS 103 097 v1.2.1 - levels currently undefined
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    // section 7.4.1 in TS 103 097 v1.2.1
    // set subject attributes
    // set the verification_key
    Uncompressed coordinates;
    coordinates.x.assign(subject_key.public_key.x.begin(), subject_key.public_key.x.end());
    coordinates.y.assign(subject_key.public_key.y.begin(), subject_key.public_key.y.end());
    EccPoint ecc_point = coordinates;
    ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = ecc_point;
    VerificationKey verification_key;
    verification_key.key = ecdsa;
    certificate.subject_attributes.push_back(verification_key);

    // section 6.7 in TS 103 097 v1.2.1
    // set validity restriction
    StartAndEndValidity start_and_end;
    start_and_end.start_validity = convert_time32(time_now - std::chrono::hours(1));
    start_and_end.end_validity = convert_time32(time_now + std::chrono::hours(24 * validity_days));
    certificate.validity_restriction.push_back(start_and_end);

    std::cout << "Signing certificate... ";

    sort(certificate);
    vanetza::ByteBuffer data_buffer = convert_for_signing(certificate);
    certificate.signature = crypto_backend.sign_data(subject_key.private_key, data_buffer);

    std::cout << "OK" << std::endl;

    return certificate;
}

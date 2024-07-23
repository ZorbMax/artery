// SelfRevocationMetrics.h
#pragma once

#include <vanetza/security/certificate.hpp>

#include <map>
#include <string>
#include <vector>

class SelfRevocationMetrics
{
public:
    void recordRevocation(const vanetza::security::HashedId8& hashedId, double simulationTime);
    void recordHeartbeat(size_t messageSize, double simulationTime);
    void recordActiveVehicleCount(size_t count, double simulationTime);
    void recordCertificateIssuance(const vanetza::security::HashedId8& hashedId, double simulationTime);

    void printMetrics() const;
    void exportToCSV(const std::string& filename) const;

private:
    struct CertificateEvent {
        vanetza::security::HashedId8 hashedId;
        double issuanceTime;
        double revocationTime;
        bool revoked;
    };

    struct HeartbeatMessage {
        size_t size;
        double time;
    };

    std::vector<CertificateEvent> certificateEvents;
    std::vector<HeartbeatMessage> heartbeatMessages;
    std::map<double, size_t> activeVehicleCounts;

    double calculateAverageCertificateLifetime() const;
    double calculateTotalHeartbeatOverhead() const;
    double calculateAverageActiveVehicles() const;
    double calculateRevocationRate() const;

    static std::string convertToHexString(const vanetza::security::HashedId8& hashedId);
};
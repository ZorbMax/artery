// SelfRevocationMetrics.cpp
#include "SelfRevocationMetrics.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>

void SelfRevocationMetrics::recordRevocation(const vanetza::security::HashedId8& hashedId, double simulationTime)
{
    auto it = std::find_if(certificateEvents.begin(), certificateEvents.end(), [&hashedId](const CertificateEvent& event) {
        return event.hashedId == hashedId && !event.revoked;
    });

    if (it != certificateEvents.end()) {
        it->revocationTime = simulationTime;
        it->revoked = true;
    }
}

void SelfRevocationMetrics::recordHeartbeat(size_t messageSize, double simulationTime)
{
    heartbeatMessages.push_back({messageSize, simulationTime});
}

void SelfRevocationMetrics::recordActiveVehicleCount(size_t count, double simulationTime)
{
    activeVehicleCounts[simulationTime] = count;
}

void SelfRevocationMetrics::recordCertificateIssuance(const vanetza::security::HashedId8& hashedId, double simulationTime)
{
    certificateEvents.push_back({hashedId, simulationTime, 0.0, false});
}

double SelfRevocationMetrics::calculateAverageCertificateLifetime() const
{
    std::vector<double> lifetimes;
    for (const auto& event : certificateEvents) {
        if (event.revoked) {
            lifetimes.push_back(event.revocationTime - event.issuanceTime);
        }
    }

    if (lifetimes.empty())
        return 0.0;

    return std::accumulate(lifetimes.begin(), lifetimes.end(), 0.0) / lifetimes.size();
}

double SelfRevocationMetrics::calculateTotalHeartbeatOverhead() const
{
    return std::accumulate(heartbeatMessages.begin(), heartbeatMessages.end(), 0.0, [](double sum, const HeartbeatMessage& msg) { return sum + msg.size; });
}

double SelfRevocationMetrics::calculateAverageActiveVehicles() const
{
    if (activeVehicleCounts.empty())
        return 0.0;

    double sum = std::accumulate(
        activeVehicleCounts.begin(), activeVehicleCounts.end(), 0.0, [](double sum, const std::pair<double, size_t>& count) { return sum + count.second; });

    return sum / activeVehicleCounts.size();
}

double SelfRevocationMetrics::calculateRevocationRate() const
{
    if (certificateEvents.empty())
        return 0.0;
    size_t revokedCount = std::count_if(certificateEvents.begin(), certificateEvents.end(), [](const CertificateEvent& event) { return event.revoked; });
    return static_cast<double>(revokedCount) / certificateEvents.size();
}

void SelfRevocationMetrics::printMetrics() const
{
    std::cout << "Average Certificate Lifetime: " << calculateAverageCertificateLifetime() << " simulation time units\n";
    std::cout << "Total Heartbeat Overhead: " << calculateTotalHeartbeatOverhead() << " bytes\n";
    std::cout << "Average Active Vehicles: " << calculateAverageActiveVehicles() << "\n";
    std::cout << "Revocation Rate: " << calculateRevocationRate() * 100 << "%\n";
}

void SelfRevocationMetrics::exportToCSV(const std::string& baseFilename) const
{
    // Certificate events CSV
    std::ofstream certFile(baseFilename + "_certificates.csv");
    certFile << "Simulation Time,Event Type,HashedId8\n";
    for (const auto& event : certificateEvents) {
        certFile << event.issuanceTime << ",CertificateIssuance," << convertToHexString(event.hashedId) << "\n";
        if (event.revoked) {
            certFile << event.revocationTime << ",Revocation," << convertToHexString(event.hashedId) << "\n";
        }
    }

    // Heartbeat messages CSV
    std::ofstream heartbeatFile(baseFilename + "_heartbeats.csv");
    heartbeatFile << "Simulation Time,Message Size\n";
    for (const auto& msg : heartbeatMessages) {
        heartbeatFile << msg.time << "," << msg.size << "\n";
    }

    // Active vehicle counts CSV
    std::ofstream vehicleFile(baseFilename + "_active_vehicles.csv");
    vehicleFile << "Simulation Time,Active Vehicles\n";
    for (const auto& entry : activeVehicleCounts) {
        vehicleFile << entry.first << "," << entry.second << "\n";
    }
}

std::string SelfRevocationMetrics::convertToHexString(const vanetza::security::HashedId8& hashedId)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < hashedId.size(); ++i) {
        ss << std::setw(2) << static_cast<int>(hashedId[i]);
    }
    return ss.str();
}
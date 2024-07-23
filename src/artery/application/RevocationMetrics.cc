#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <numeric>
#include <iostream>
#include <memory>

class RevocationMetrics {
public:
    void recordRevocation(const std::string& vehicleId, double simulationTime) {
        revocationEvents.push_back({vehicleId, simulationTime, 0.0, false});
    }

    void recordMessageDiscard(const std::string& revokedVehicleId, double simulationTime) {
        auto it = std::find_if(revocationEvents.begin(), revocationEvents.end(),
            [&revokedVehicleId](const RevocationEvent& event) {
                return event.vehicleId == revokedVehicleId && !event.discarded;
            });

        if (it != revocationEvents.end()) {
            it->firstDiscardTime = simulationTime;
            it->discarded = true;
        }
    }

    void recordRevocationMessage(size_t messageSize, double simulationTime) {
        revocationMessages.push_back({messageSize, simulationTime});
    }

    void printMetrics() const {
        double avgDelay = calculateAverageRevocationDelay();
        double totalOverhead = calculateTotalNetworkOverhead();

        std::cout << "Average Revocation Delay: " << avgDelay << " simulation time units\n";
        std::cout << "Total Network Overhead: " << totalOverhead << " bytes\n";
    }

    void exportMetrics(const std::string& filename) const {
        std::ofstream file(filename);
        file << "Metric,Value\n";
        file << "Average Revocation Delay," << calculateAverageRevocationDelay() << "\n";
        file << "Total Network Overhead," << calculateTotalNetworkOverhead() << "\n";
    }

    void exportToCSV(const std::string& filename) const {
        std::ofstream file(filename);
        file << "Simulation Time,Event Type,Vehicle ID,Message Size\n";
        
        for (const auto& event : revocationEvents) {
            file << event.revocationTime << ",Revocation," << event.vehicleId << ",\n";
            if (event.discarded) {
                file << event.firstDiscardTime << ",Discard," << event.vehicleId << ",\n";
            }
        }
        
        for (const auto& msg : revocationMessages) {
            file << msg.second << ",RevocationMessage,," << msg.first << "\n";
        }
    }

private:
    struct RevocationEvent {
        std::string vehicleId;
        double revocationTime;
        double firstDiscardTime;
        bool discarded;
    };

    std::vector<RevocationEvent> revocationEvents;
    std::vector<std::pair<size_t, double>> revocationMessages; // <message size, time>

    double calculateAverageRevocationDelay() const {
        std::vector<double> delays;
        for (const auto& event : revocationEvents) {
            if (event.discarded) {
                delays.push_back(event.firstDiscardTime - event.revocationTime);
            }
        }

        if (delays.empty()) return 0.0;

        return std::accumulate(delays.begin(), delays.end(), 0.0) / delays.size();
    }

    double calculateTotalNetworkOverhead() const {
        return std::accumulate(revocationMessages.begin(), revocationMessages.end(), 0.0,
            [](double sum, const std::pair<size_t, double>& msg) {
                return sum + msg.first;
            });
    }
};
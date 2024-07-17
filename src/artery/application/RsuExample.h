//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef RSUEXAMPLE_H_
#define RSUEXAMPLE_H_

#include "PseudonymMessageHandler.h"
#include "CertificateManager.h"

#include "artery/application/ItsG5Service.h"
#include "artery/application/NetworkInterface.h"
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/backend.hpp>
#include "vanetza/security/ecdsa256.hpp"

#include "CRLMessage_m.h"
#include "artery/application/ItsG5BaseService.h"
#include "artery/application/ItsG5Service.h"

#include <omnetpp.h>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>

#include <set>
#include <vector>

namespace artery
{

class RsuExample : public ItsG5Service
{
    public:
        RsuExample();
        ~RsuExample();

        void indicate(const vanetza::btp::DataIndication&, omnetpp::cPacket*, const NetworkInterface&) override;
        void trigger() override;
        void receiveSignal(omnetpp::cComponent*, omnetpp::simsignal_t, omnetpp::cObject*, omnetpp::cObject*) override;

    protected:
        void initialize() override;
        void finish() override;
        void handleMessage(omnetpp::cMessage*) override;

    private:
        omnetpp::cMessage* m_self_msg;
        bool boolPseudo;
        bool boolEnroll;

        omnetpp::cMessage* mTriggerMessage;

        CRLMessage* createAndPopulateCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates);
        std::vector<vanetza::security::Certificate> generateDummyRevokedCertificates(size_t count);
};

} // namespace artery

#endif /* RsuExample_H_ */

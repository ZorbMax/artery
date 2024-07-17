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

#ifndef EXAMPLESERVICE_H_
#define EXAMPLESERVICE_H_

#include "PseudonymMessageHandler.h"
#include "CertificateManager.h"

#include "artery/application/ItsG5Service.h"
#include "artery/application/NetworkInterface.h"
#include <vanetza/security/backend.hpp>
#include "vanetza/security/ecdsa256.hpp"

#include <omnetpp.h>
#include <memory>

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "CertificateManager.h"
#include "V2VMessageHandler.h"

namespace artery
{

class ExampleService : public ItsG5Service
{
    public:
        ExampleService();
        ~ExampleService();

        void indicate(const vanetza::btp::DataIndication&, omnetpp::cPacket*, const NetworkInterface&) override;
        void trigger() override;
        void receiveSignal(omnetpp::cComponent*, omnetpp::simsignal_t, omnetpp::cObject*, omnetpp::cObject*) override;

    protected:
        void initialize() override;
        void finish() override;
        void handleMessage(omnetpp::cMessage*) override;

    private:
        omnetpp::cMessage* m_self_msg;
        std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
        vanetza::security::ecdsa256::KeyPair mRootKeyPair;
        vanetza::security::ecdsa256::KeyPair mKeyPair;
        vanetza::security::Certificate mCertificate;
        std::string mId;
        std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;
        std::vector<vanetza::security::Certificate> mCertVector; // Store certificates of pseudonyms
        bool boolPseudo;
        bool boolEnroll;

        void handleCRLMessage(CRLMessage* crlMessage);
        void processMessage(V2VMessage* v2vMessage);
        void discardMessage(omnetpp::cPacket* packet);

        std::unique_ptr<CertificateManager> mCertificateManager;
        std::unique_ptr<CRLMessageHandler> mCRLHandler;
        std::unique_ptr<V2VMessageHandler> mV2VHandler;
        
};

} // namespace artery

#endif /* EXAMPLESERVICE_H_ */

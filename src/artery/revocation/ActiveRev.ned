package artery.revocation;

import artery.StaticNodeManager;
import inet.environment.contract.IPhysicalEnvironment;
import inet.physicallayer.contract.packetlevel.IRadioMedium;
import traci.Manager;

network ActiveRev
{
    parameters:
        int numRoadSideUnits = default(1);
        int numNodes = default(10);
        traci.mapper.vehicleType = default("artery.revocation.Car");
        traci.nodes.vehicleSinkModule = default(".mobility");

    submodules:
        traci: Manager {
            parameters:
                @display("p=20,20");
        }

        radioMedium: <default("Ieee80211ScalarRadioMedium")> like IRadioMedium {
            parameters:
                @display("p=60,20");
                mediumLimitCache.carrierFrequency = 5.9GHz;
        }

        rsu[numRoadSideUnits]: RsuNode {
            parameters:
                mobility.initFromDisplayString = false;
        }

        staticNodes: StaticNodeManager {
            parameters:
                @display("p=20,40");
                waitForTraCI = default(true);
        }

        node[numNodes]: VehicleNode {
            parameters:
                @display("p=60,60");
        }
}

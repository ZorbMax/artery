package artery.application;

simple SelfRevocationAuthService
{
    parameters:
        @class(SelfRevocationAuthService);
        double validityWindow @unit(s) = default(50s);
        double heartbeatInterval @unit(s) = default(3s);
        double minRevocationInterval @unit(s) = default(40s);
        double maxRevocationInterval @unit(s) = default(80s);
        double dropProbability = default(0.35);
        double delayProbability = default(0.35);
        double delayMean @unit(s) = default(2s);
        double delayStdDev @unit(s) = default(0.3s);
        string revocationMode = default("interval");
}

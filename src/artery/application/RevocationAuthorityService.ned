package artery.application;

simple RevocationAuthorityService
{
    parameters:
        @class(RevocationAuthorityService);
        double crlGenInterval @unit(s) = default(3s);
        double revocationInterval @unit(s) = default(8s);
        double dropProbability = default(0.35);
        double delayProbability = default(0.35);
        double delayMean @unit(s) = default(2s);
        double delayStdDev @unit(s) = default(0.3s);
}

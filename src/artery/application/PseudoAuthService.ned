package artery.application;

simple PseudoAuthService
{
    parameters:
        @class(PseudoAuthService);
        double revocationInterval @unit(s) = default(8s);
        double minRevocationInterval @unit(s) = default(45s);
        double maxRevocationInterval @unit(s) = default(85s);
        double dropProbability = default(0.35);
        double delayProbability = default(0.35);
        double delayMean @unit(s) = default(2s);
        double delayStdDev @unit(s) = default(0.3s);
        string revocationMode = default("interval");
}

package artery.application;

simple SelfRevocationAuthService
{
    parameters:
        @class(SelfRevocationAuthService);
        double validityWindow @unit(s) = default(50s);
        double heartbeatInterval @unit(s) = default(3s);
        double revocationInterval @unit(s) = default(20s);
}

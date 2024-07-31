package artery.application;

simple PseudoAuthService
{
    parameters:
        @class(PseudoAuthService);
        double revocationInterval @unit(s) = default(8s);
}

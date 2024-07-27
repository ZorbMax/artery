package artery.application;

simple RevocationAuthorityService
{
    parameters:
        @class(RevocationAuthorityService);
        double crlGenInterval @unit(s) = default(3s);
        double revocationInterval @unit(s) = default(8s);
}

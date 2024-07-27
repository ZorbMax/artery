package artery.application;

simple VehicleHBService like ItsG5Service
{
    parameters:
        @class(VehicleHBService);
        double validityWindow @unit(s) = default(50s);
}
#include "VanetzaDescriptors.h"

vanetza__security__EcdsaSignatureDescriptor::vanetza__security__EcdsaSignatureDescriptor() :
    omnetpp::cClassDescriptor("vanetza::security::EcdsaSignature", "omnetpp::cObject")
{
    propertynames = nullptr;
}

vanetza__security__EcdsaSignatureDescriptor::~vanetza__security__EcdsaSignatureDescriptor()
{
    delete[] propertynames;
}

bool vanetza__security__EcdsaSignatureDescriptor::doesSupport(omnetpp::cObject* obj) const
{
    return dynamic_cast<vanetza::security::EcdsaSignature*>(obj) != nullptr;
}

const char** vanetza__security__EcdsaSignatureDescriptor::getPropertyNames() const
{
    if (!propertynames) {
        static const char* names[] = {"existingClass", nullptr};
        omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
        const char** basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
        propertynames = mergeLists(basenames, names);
    }
    return propertynames;
}

const char* vanetza__security__EcdsaSignatureDescriptor::getProperty(const char* propertyname) const
{
    if (!strcmp(propertyname, "existingClass"))
        return "";
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : nullptr;
}

int vanetza__security__EcdsaSignatureDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? 0 + basedesc->getFieldCount() : 0;
}

unsigned int vanetza__security__EcdsaSignatureDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeFlags(field);
        field -= basedesc->getFieldCount();
    }
    return 0;
}

const char* vanetza__security__EcdsaSignatureDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldName(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

int vanetza__security__EcdsaSignatureDescriptor::findField(const char* fieldName) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->findField(fieldName) : -1;
}

const char* vanetza__security__EcdsaSignatureDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeString(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

const char** vanetza__security__EcdsaSignatureDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldPropertyNames(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        default:
            return nullptr;
    }
}

const char* vanetza__security__EcdsaSignatureDescriptor::getFieldProperty(int field, const char* propertyname) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldProperty(field, propertyname);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        default:
            return nullptr;
    }
}

int vanetza__security__EcdsaSignatureDescriptor::getFieldArraySize(void* object, int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldArraySize(object, field);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
    (void)pp;
    switch (field) {
        default:
            return 0;
    }
}

const char* vanetza__security__EcdsaSignatureDescriptor::getFieldDynamicTypeString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldDynamicTypeString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}

std::string vanetza__security__EcdsaSignatureDescriptor::getFieldValueAsString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldValueAsString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
    (void)pp;
    switch (field) {
        default:
            return "";
    }
}

bool vanetza__security__EcdsaSignatureDescriptor::setFieldValueAsString(void* object, int field, int i, const char* value) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->setFieldValueAsString(object, field, i, value);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
    (void)pp;
    switch (field) {
        default:
            return false;
    }
}

const char* vanetza__security__EcdsaSignatureDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructName(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

void* vanetza__security__EcdsaSignatureDescriptor::getFieldStructValuePointer(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructValuePointer(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}

vanetza__security__CertificateDescriptor::vanetza__security__CertificateDescriptor() :
    omnetpp::cClassDescriptor("vanetza::security::Certificate", "omnetpp::cObject")
{
    propertynames = nullptr;
}

vanetza__security__CertificateDescriptor::~vanetza__security__CertificateDescriptor()
{
    delete[] propertynames;
}

bool vanetza__security__CertificateDescriptor::doesSupport(omnetpp::cObject* obj) const
{
    return dynamic_cast<vanetza::security::Certificate*>(obj) != nullptr;
}

const char** vanetza__security__CertificateDescriptor::getPropertyNames() const
{
    if (!propertynames) {
        static const char* names[] = {"existingClass", nullptr};
        omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
        const char** basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
        propertynames = mergeLists(basenames, names);
    }
    return propertynames;
}

const char* vanetza__security__CertificateDescriptor::getProperty(const char* propertyname) const
{
    if (!strcmp(propertyname, "existingClass"))
        return "";
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : nullptr;
}

int vanetza__security__CertificateDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? 0 + basedesc->getFieldCount() : 0;
}

unsigned int vanetza__security__CertificateDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeFlags(field);
        field -= basedesc->getFieldCount();
    }
    return 0;
}

const char* vanetza__security__CertificateDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldName(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

int vanetza__security__CertificateDescriptor::findField(const char* fieldName) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->findField(fieldName) : -1;
}

const char* vanetza__security__CertificateDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeString(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

const char** vanetza__security__CertificateDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldPropertyNames(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        default:
            return nullptr;
    }
}

const char* vanetza__security__CertificateDescriptor::getFieldProperty(int field, const char* propertyname) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldProperty(field, propertyname);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        default:
            return nullptr;
    }
}

int vanetza__security__CertificateDescriptor::getFieldArraySize(void* object, int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldArraySize(object, field);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
    (void)pp;
    switch (field) {
        default:
            return 0;
    }
}

const char* vanetza__security__CertificateDescriptor::getFieldDynamicTypeString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldDynamicTypeString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}

std::string vanetza__security__CertificateDescriptor::getFieldValueAsString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldValueAsString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
    (void)pp;
    switch (field) {
        default:
            return "";
    }
}

bool vanetza__security__CertificateDescriptor::setFieldValueAsString(void* object, int field, int i, const char* value) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->setFieldValueAsString(object, field, i, value);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
    (void)pp;
    switch (field) {
        default:
            return false;
    }
}

const char* vanetza__security__CertificateDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructName(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

void* vanetza__security__CertificateDescriptor::getFieldStructValuePointer(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructValuePointer(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}
#ifndef VANETZA_DESCRIPTORS_H
#define VANETZA_DESCRIPTORS_H

#include <omnetpp.h>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>

// EcdsaSignature Descriptor
class vanetza__security__EcdsaSignatureDescriptor : public omnetpp::cClassDescriptor
{
private:
    mutable const char** propertynames;

public:
    vanetza__security__EcdsaSignatureDescriptor();
    virtual ~vanetza__security__EcdsaSignatureDescriptor();

    virtual bool doesSupport(omnetpp::cObject* obj) const override;
    virtual const char** getPropertyNames() const override;
    virtual const char* getProperty(const char* propertyname) const override;
    virtual int getFieldCount() const override;
    virtual const char* getFieldName(int field) const override;
    virtual int findField(const char* fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char* getFieldTypeString(int field) const override;
    virtual const char** getFieldPropertyNames(int field) const override;
    virtual const char* getFieldProperty(int field, const char* propertyname) const override;
    virtual int getFieldArraySize(void* object, int field) const override;
    virtual const char* getFieldDynamicTypeString(void* object, int field, int i) const override;
    virtual std::string getFieldValueAsString(void* object, int field, int i) const override;
    virtual bool setFieldValueAsString(void* object, int field, int i, const char* value) const override;
    virtual const char* getFieldStructName(int field) const override;
    virtual void* getFieldStructValuePointer(void* object, int field, int i) const override;
};

// Certificate Descriptor
class vanetza__security__CertificateDescriptor : public omnetpp::cClassDescriptor
{
private:
    mutable const char** propertynames;

public:
    vanetza__security__CertificateDescriptor();
    virtual ~vanetza__security__CertificateDescriptor();

    virtual bool doesSupport(omnetpp::cObject* obj) const override;
    virtual const char** getPropertyNames() const override;
    virtual const char* getProperty(const char* propertyname) const override;
    virtual int getFieldCount() const override;
    virtual const char* getFieldName(int field) const override;
    virtual int findField(const char* fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char* getFieldTypeString(int field) const override;
    virtual const char** getFieldPropertyNames(int field) const override;
    virtual const char* getFieldProperty(int field, const char* propertyname) const override;
    virtual int getFieldArraySize(void* object, int field) const override;
    virtual const char* getFieldDynamicTypeString(void* object, int field, int i) const override;
    virtual std::string getFieldValueAsString(void* object, int field, int i) const override;
    virtual bool setFieldValueAsString(void* object, int field, int i, const char* value) const override;
    virtual const char* getFieldStructName(int field) const override;
    virtual void* getFieldStructValuePointer(void* object, int field, int i) const override;
};

#endif  // VANETZA_DESCRIPTORS_H

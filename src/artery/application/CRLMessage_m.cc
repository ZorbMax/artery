//
// Generated file, do not edit! Created by nedtool 5.6 from CRLMessage.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#pragma warning(disable : 4101)
#pragma warning(disable : 4065)
#endif

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc++98-compat"
#pragma clang diagnostic ignored "-Wunreachable-code-break"
#pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#pragma GCC diagnostic ignored "-Wfloat-conversion"
#endif

#include "CRLMessage_m.h"

#include <iostream>
#include <sstream>

namespace omnetpp
{

// Template pack/unpack rules. They are declared *after* a1l type-specific pack functions for multiple reasons.
// They are in the omnetpp namespace, to allow them to be found by argument-dependent lookup via the cCommBuffer argument

// Packing/unpacking an std::vector
template <typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer* buffer, const std::vector<T, A>& v)
{
    int n = v.size();
    doParsimPacking(buffer, n);
    for (int i = 0; i < n; i++)
        doParsimPacking(buffer, v[i]);
}

template <typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer* buffer, std::vector<T, A>& v)
{
    int n;
    doParsimUnpacking(buffer, n);
    v.resize(n);
    for (int i = 0; i < n; i++)
        doParsimUnpacking(buffer, v[i]);
}

// Packing/unpacking an std::list
template <typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer* buffer, const std::list<T, A>& l)
{
    doParsimPacking(buffer, (int)l.size());
    for (typename std::list<T, A>::const_iterator it = l.begin(); it != l.end(); ++it)
        doParsimPacking(buffer, (T&)*it);
}

template <typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer* buffer, std::list<T, A>& l)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        l.push_back(T());
        doParsimUnpacking(buffer, l.back());
    }
}

// Packing/unpacking an std::set
template <typename T, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer* buffer, const std::set<T, Tr, A>& s)
{
    doParsimPacking(buffer, (int)s.size());
    for (typename std::set<T, Tr, A>::const_iterator it = s.begin(); it != s.end(); ++it)
        doParsimPacking(buffer, *it);
}

template <typename T, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer* buffer, std::set<T, Tr, A>& s)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        T x;
        doParsimUnpacking(buffer, x);
        s.insert(x);
    }
}

// Packing/unpacking an std::map
template <typename K, typename V, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer* buffer, const std::map<K, V, Tr, A>& m)
{
    doParsimPacking(buffer, (int)m.size());
    for (typename std::map<K, V, Tr, A>::const_iterator it = m.begin(); it != m.end(); ++it) {
        doParsimPacking(buffer, it->first);
        doParsimPacking(buffer, it->second);
    }
}

template <typename K, typename V, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer* buffer, std::map<K, V, Tr, A>& m)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        K k;
        V v;
        doParsimUnpacking(buffer, k);
        doParsimUnpacking(buffer, v);
        m[k] = v;
    }
}

// Default pack/unpack function for arrays
template <typename T>
void doParsimArrayPacking(omnetpp::cCommBuffer* b, const T* t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimPacking(b, t[i]);
}

template <typename T>
void doParsimArrayUnpacking(omnetpp::cCommBuffer* b, T* t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimUnpacking(b, t[i]);
}

// Default rule to prevent compiler from choosing base class' doParsimPacking() function
template <typename T>
void doParsimPacking(omnetpp::cCommBuffer*, const T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimPacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

template <typename T>
void doParsimUnpacking(omnetpp::cCommBuffer*, T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimUnpacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

}  // namespace omnetpp


// forward
template <typename T, typename A>
std::ostream& operator<<(std::ostream& out, const std::vector<T, A>& vec);

// Template rule which fires if a struct or class doesn't have operator<<
template <typename T>
inline std::ostream& operator<<(std::ostream& out, const T&)
{
    return out;
}

// operator<< for std::vector<T>
template <typename T, typename A>
inline std::ostream& operator<<(std::ostream& out, const std::vector<T, A>& vec)
{
    out.put('{');
    for (typename std::vector<T, A>::const_iterator it = vec.begin(); it != vec.end(); ++it) {
        if (it != vec.begin()) {
            out.put(',');
            out.put(' ');
        }
        out << *it;
    }
    out.put('}');

    char buf[32];
    sprintf(buf, " (size=%u)", (unsigned int)vec.size());
    out.write(buf, strlen(buf));
    return out;
}

class vanetza__security__HashedId8Descriptor : public omnetpp::cClassDescriptor
{
private:
    mutable const char** propertynames;

public:
    vanetza__security__HashedId8Descriptor();
    virtual ~vanetza__security__HashedId8Descriptor();

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

Register_ClassDescriptor(vanetza__security__HashedId8Descriptor)

    vanetza__security__HashedId8Descriptor::vanetza__security__HashedId8Descriptor() :
    omnetpp::cClassDescriptor("vanetza::security::HashedId8", "omnetpp::cObject")
{
    propertynames = nullptr;
}

vanetza__security__HashedId8Descriptor::~vanetza__security__HashedId8Descriptor()
{
    delete[] propertynames;
}

bool vanetza__security__HashedId8Descriptor::doesSupport(omnetpp::cObject* obj) const
{
    return dynamic_cast<vanetza::security::HashedId8*>(obj) != nullptr;
}

const char** vanetza__security__HashedId8Descriptor::getPropertyNames() const
{
    if (!propertynames) {
        static const char* names[] = {"existingClass", nullptr};
        omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
        const char** basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
        propertynames = mergeLists(basenames, names);
    }
    return propertynames;
}

const char* vanetza__security__HashedId8Descriptor::getProperty(const char* propertyname) const
{
    if (!strcmp(propertyname, "existingClass"))
        return "";
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : nullptr;
}

int vanetza__security__HashedId8Descriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? 0 + basedesc->getFieldCount() : 0;
}

unsigned int vanetza__security__HashedId8Descriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeFlags(field);
        field -= basedesc->getFieldCount();
    }
    return 0;
}

const char* vanetza__security__HashedId8Descriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldName(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

int vanetza__security__HashedId8Descriptor::findField(const char* fieldName) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->findField(fieldName) : -1;
}

const char* vanetza__security__HashedId8Descriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeString(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

const char** vanetza__security__HashedId8Descriptor::getFieldPropertyNames(int field) const
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

const char* vanetza__security__HashedId8Descriptor::getFieldProperty(int field, const char* propertyname) const
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

int vanetza__security__HashedId8Descriptor::getFieldArraySize(void* object, int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldArraySize(object, field);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::HashedId8* pp = (vanetza::security::HashedId8*)object;
    (void)pp;
    switch (field) {
        default:
            return 0;
    }
}

const char* vanetza__security__HashedId8Descriptor::getFieldDynamicTypeString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldDynamicTypeString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::HashedId8* pp = (vanetza::security::HashedId8*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}

std::string vanetza__security__HashedId8Descriptor::getFieldValueAsString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldValueAsString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::HashedId8* pp = (vanetza::security::HashedId8*)object;
    (void)pp;
    switch (field) {
        default:
            return "";
    }
}

bool vanetza__security__HashedId8Descriptor::setFieldValueAsString(void* object, int field, int i, const char* value) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->setFieldValueAsString(object, field, i, value);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::HashedId8* pp = (vanetza::security::HashedId8*)object;
    (void)pp;
    switch (field) {
        default:
            return false;
    }
}

const char* vanetza__security__HashedId8Descriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructName(field);
        field -= basedesc->getFieldCount();
    }
    return nullptr;
}

void* vanetza__security__HashedId8Descriptor::getFieldStructValuePointer(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructValuePointer(object, field, i);
        field -= basedesc->getFieldCount();
    }
    vanetza::security::HashedId8* pp = (vanetza::security::HashedId8*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}

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

Register_ClassDescriptor(vanetza__security__EcdsaSignatureDescriptor)

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

Register_ClassDescriptor(vanetza__security__CertificateDescriptor)

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

Register_Class(CRLMessage)

CRLMessage::CRLMessage(const char* name, short kind) : ::omnetpp::cPacket(name, kind)
{
    this->mTimestamp = 0;
    mRevokedCertificates_arraysize = 0;
    this->mRevokedCertificates = 0;
}

CRLMessage::CRLMessage(const CRLMessage& other) : ::omnetpp::cPacket(other)
{
    mRevokedCertificates_arraysize = 0;
    this->mRevokedCertificates = 0;
    copy(other);
}

CRLMessage::~CRLMessage()
{
    delete[] this->mRevokedCertificates;
}

CRLMessage& CRLMessage::operator=(const CRLMessage& other)
{
    if (this == &other)
        return *this;
    ::omnetpp::cMessage::operator=(other);
    copy(other);
    return *this;
}

void CRLMessage::copy(const CRLMessage& other)
{
    this->mTimestamp = other.mTimestamp;
    delete[] this->mRevokedCertificates;
    this->mRevokedCertificates = (other.mRevokedCertificates_arraysize == 0) ? nullptr : new vanetza::security::HashedId8[other.mRevokedCertificates_arraysize];
    mRevokedCertificates_arraysize = other.mRevokedCertificates_arraysize;
    for (unsigned int i = 0; i < mRevokedCertificates_arraysize; i++)
        this->mRevokedCertificates[i] = other.mRevokedCertificates[i];
    this->mSignature = other.mSignature;
    this->mSignerCertificate = other.mSignerCertificate;
}

void CRLMessage::parsimPack(omnetpp::cCommBuffer* b) const
{
    ::omnetpp::cMessage::parsimPack(b);
    doParsimPacking(b, this->mTimestamp);
    b->pack(mRevokedCertificates_arraysize);
    doParsimArrayPacking(b, this->mRevokedCertificates, mRevokedCertificates_arraysize);
    doParsimPacking(b, this->mSignature);
    doParsimPacking(b, this->mSignerCertificate);
}

void CRLMessage::parsimUnpack(omnetpp::cCommBuffer* b)
{
    ::omnetpp::cMessage::parsimUnpack(b);
    doParsimUnpacking(b, this->mTimestamp);
    delete[] this->mRevokedCertificates;
    b->unpack(mRevokedCertificates_arraysize);
    if (mRevokedCertificates_arraysize == 0) {
        this->mRevokedCertificates = 0;
    } else {
        this->mRevokedCertificates = new vanetza::security::HashedId8[mRevokedCertificates_arraysize];
        doParsimArrayUnpacking(b, this->mRevokedCertificates, mRevokedCertificates_arraysize);
    }
    doParsimUnpacking(b, this->mSignature);
    doParsimUnpacking(b, this->mSignerCertificate);
}

::omnetpp::simtime_t CRLMessage::getMTimestamp() const
{
    return this->mTimestamp;
}

void CRLMessage::setMTimestamp(::omnetpp::simtime_t mTimestamp)
{
    this->mTimestamp = mTimestamp;
}

void CRLMessage::setMRevokedCertificatesArraySize(unsigned int size)
{
    vanetza::security::HashedId8* mRevokedCertificates2 = (size == 0) ? nullptr : new vanetza::security::HashedId8[size];
    unsigned int sz = mRevokedCertificates_arraysize < size ? mRevokedCertificates_arraysize : size;
    for (unsigned int i = 0; i < sz; i++)
        mRevokedCertificates2[i] = this->mRevokedCertificates[i];
    mRevokedCertificates_arraysize = size;
    delete[] this->mRevokedCertificates;
    this->mRevokedCertificates = mRevokedCertificates2;
}

unsigned int CRLMessage::getMRevokedCertificatesArraySize() const
{
    return mRevokedCertificates_arraysize;
}

vanetza::security::HashedId8& CRLMessage::getMRevokedCertificates(unsigned int k)
{
    if (k >= mRevokedCertificates_arraysize)
        throw omnetpp::cRuntimeError("Array of size %d indexed by %d", mRevokedCertificates_arraysize, k);
    return this->mRevokedCertificates[k];
}

void CRLMessage::setMRevokedCertificates(unsigned int k, const vanetza::security::HashedId8& mRevokedCertificates)
{
    if (k >= mRevokedCertificates_arraysize)
        throw omnetpp::cRuntimeError("Array of size %d indexed by %d", mRevokedCertificates_arraysize, k);
    this->mRevokedCertificates[k] = mRevokedCertificates;
}

vanetza::security::EcdsaSignature& CRLMessage::getMSignature()
{
    return this->mSignature;
}

void CRLMessage::setMSignature(const vanetza::security::EcdsaSignature& mSignature)
{
    this->mSignature = mSignature;
}

vanetza::security::Certificate& CRLMessage::getMSignerCertificate()
{
    return this->mSignerCertificate;
}

void CRLMessage::setMSignerCertificate(const vanetza::security::Certificate& mSignerCertificate)
{
    this->mSignerCertificate = mSignerCertificate;
}

class CRLMessageDescriptor : public omnetpp::cClassDescriptor
{
private:
    mutable const char** propertynames;

public:
    CRLMessageDescriptor();
    virtual ~CRLMessageDescriptor();

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

Register_ClassDescriptor(CRLMessageDescriptor)

    CRLMessageDescriptor::CRLMessageDescriptor() :
    omnetpp::cClassDescriptor("CRLMessage", "omnetpp::cMessage")
{
    propertynames = nullptr;
}

CRLMessageDescriptor::~CRLMessageDescriptor()
{
    delete[] propertynames;
}

bool CRLMessageDescriptor::doesSupport(omnetpp::cObject* obj) const
{
    return dynamic_cast<CRLMessage*>(obj) != nullptr;
}

const char** CRLMessageDescriptor::getPropertyNames() const
{
    if (!propertynames) {
        static const char* names[] = {nullptr};
        omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
        const char** basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
        propertynames = mergeLists(basenames, names);
    }
    return propertynames;
}

const char* CRLMessageDescriptor::getProperty(const char* propertyname) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : nullptr;
}

int CRLMessageDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? 4 + basedesc->getFieldCount() : 4;
}

unsigned int CRLMessageDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeFlags(field);
        field -= basedesc->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        FD_ISEDITABLE,
        FD_ISARRAY | FD_ISCOMPOUND | FD_ISCOBJECT,
        FD_ISCOMPOUND | FD_ISCOBJECT,
        FD_ISCOMPOUND | FD_ISCOBJECT,
    };
    return (field >= 0 && field < 4) ? fieldTypeFlags[field] : 0;
}

const char* CRLMessageDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldName(field);
        field -= basedesc->getFieldCount();
    }
    static const char* fieldNames[] = {
        "mTimestamp",
        "mRevokedCertificates",
        "mSignature",
        "mSignerCertificate",
    };
    return (field >= 0 && field < 4) ? fieldNames[field] : nullptr;
}

int CRLMessageDescriptor::findField(const char* fieldName) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    int base = basedesc ? basedesc->getFieldCount() : 0;
    if (fieldName[0] == 'm' && strcmp(fieldName, "mTimestamp") == 0)
        return base + 0;
    if (fieldName[0] == 'm' && strcmp(fieldName, "mRevokedCertificates") == 0)
        return base + 1;
    if (fieldName[0] == 'm' && strcmp(fieldName, "mSignature") == 0)
        return base + 2;
    if (fieldName[0] == 'm' && strcmp(fieldName, "mSignerCertificate") == 0)
        return base + 3;
    return basedesc ? basedesc->findField(fieldName) : -1;
}

const char* CRLMessageDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeString(field);
        field -= basedesc->getFieldCount();
    }
    static const char* fieldTypeStrings[] = {
        "simtime_t",
        "vanetza::security::HashedId8",
        "vanetza::security::EcdsaSignature",
        "vanetza::security::Certificate",
    };
    return (field >= 0 && field < 4) ? fieldTypeStrings[field] : nullptr;
}

const char** CRLMessageDescriptor::getFieldPropertyNames(int field) const
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

const char* CRLMessageDescriptor::getFieldProperty(int field, const char* propertyname) const
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

int CRLMessageDescriptor::getFieldArraySize(void* object, int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldArraySize(object, field);
        field -= basedesc->getFieldCount();
    }
    CRLMessage* pp = (CRLMessage*)object;
    (void)pp;
    switch (field) {
        case 1:
            return pp->getMRevokedCertificatesArraySize();
        default:
            return 0;
    }
}

const char* CRLMessageDescriptor::getFieldDynamicTypeString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldDynamicTypeString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    CRLMessage* pp = (CRLMessage*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}

std::string CRLMessageDescriptor::getFieldValueAsString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldValueAsString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    CRLMessage* pp = (CRLMessage*)object;
    (void)pp;
    switch (field) {
        case 0:
            return simtime2string(pp->getMTimestamp());
        case 1: {
            std::stringstream out;
            out << pp->getMRevokedCertificates(i);
            return out.str();
        }
        case 2: {
            std::stringstream out;
            out << pp->getMSignature();
            return out.str();
        }
        case 3: {
            std::stringstream out;
            out << pp->getMSignerCertificate();
            return out.str();
        }
        default:
            return "";
    }
}

bool CRLMessageDescriptor::setFieldValueAsString(void* object, int field, int i, const char* value) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->setFieldValueAsString(object, field, i, value);
        field -= basedesc->getFieldCount();
    }
    CRLMessage* pp = (CRLMessage*)object;
    (void)pp;
    switch (field) {
        case 0:
            pp->setMTimestamp(string2simtime(value));
            return true;
        default:
            return false;
    }
}

const char* CRLMessageDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructName(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        case 1:
            return omnetpp::opp_typename(typeid(vanetza::security::HashedId8));
        case 2:
            return omnetpp::opp_typename(typeid(vanetza::security::EcdsaSignature));
        case 3:
            return omnetpp::opp_typename(typeid(vanetza::security::Certificate));
        default:
            return nullptr;
    };
}

void* CRLMessageDescriptor::getFieldStructValuePointer(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructValuePointer(object, field, i);
        field -= basedesc->getFieldCount();
    }
    CRLMessage* pp = (CRLMessage*)object;
    (void)pp;
    switch (field) {
        case 1:
            return (void*)(&pp->getMRevokedCertificates(i));
            break;
        case 2:
            return (void*)(&pp->getMSignature());
            break;
        case 3:
            return (void*)(&pp->getMSignerCertificate());
            break;
        default:
            return nullptr;
    }
}

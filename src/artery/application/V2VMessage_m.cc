//
// Generated file, do not edit! Created by nedtool 5.6 from V2VMessage.msg.
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

#include "V2VMessage_m.h"

#include "VanetzaDescriptors.h"

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

// class vanetza__security__EcdsaSignatureDescriptor : public omnetpp::cClassDescriptor
// {
// private:
//     mutable const char** propertynames;

// public:
//     vanetza__security__EcdsaSignatureDescriptor();
//     virtual ~vanetza__security__EcdsaSignatureDescriptor();

//     virtual bool doesSupport(omnetpp::cObject* obj) const override;
//     virtual const char** getPropertyNames() const override;
//     virtual const char* getProperty(const char* propertyname) const override;
//     virtual int getFieldCount() const override;
//     virtual const char* getFieldName(int field) const override;
//     virtual int findField(const char* fieldName) const override;
//     virtual unsigned int getFieldTypeFlags(int field) const override;
//     virtual const char* getFieldTypeString(int field) const override;
//     virtual const char** getFieldPropertyNames(int field) const override;
//     virtual const char* getFieldProperty(int field, const char* propertyname) const override;
//     virtual int getFieldArraySize(void* object, int field) const override;

//     virtual const char* getFieldDynamicTypeString(void* object, int field, int i) const override;
//     virtual std::string getFieldValueAsString(void* object, int field, int i) const override;
//     virtual bool setFieldValueAsString(void* object, int field, int i, const char* value) const override;

//     virtual const char* getFieldStructName(int field) const override;
//     virtual void* getFieldStructValuePointer(void* object, int field, int i) const override;
// };

// Register_ClassDescriptor(vanetza__security__EcdsaSignatureDescriptor)

//     vanetza__security__EcdsaSignatureDescriptor::vanetza__security__EcdsaSignatureDescriptor() :
//     omnetpp::cClassDescriptor("vanetza::security::EcdsaSignature", "omnetpp::cObject")
// {
//     propertynames = nullptr;
// }

// vanetza__security__EcdsaSignatureDescriptor::~vanetza__security__EcdsaSignatureDescriptor()
// {
//     delete[] propertynames;
// }

// bool vanetza__security__EcdsaSignatureDescriptor::doesSupport(omnetpp::cObject* obj) const
// {
//     return dynamic_cast<vanetza::security::EcdsaSignature*>(obj) != nullptr;
// }

// const char** vanetza__security__EcdsaSignatureDescriptor::getPropertyNames() const
// {
//     if (!propertynames) {
//         static const char* names[] = {"existingClass", nullptr};
//         omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//         const char** basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
//         propertynames = mergeLists(basenames, names);
//     }
//     return propertynames;
// }

// const char* vanetza__security__EcdsaSignatureDescriptor::getProperty(const char* propertyname) const
// {
//     if (!strcmp(propertyname, "existingClass"))
//         return "";
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     return basedesc ? basedesc->getProperty(propertyname) : nullptr;
// }

// int vanetza__security__EcdsaSignatureDescriptor::getFieldCount() const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     return basedesc ? 0 + basedesc->getFieldCount() : 0;
// }

// unsigned int vanetza__security__EcdsaSignatureDescriptor::getFieldTypeFlags(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldTypeFlags(field);
//         field -= basedesc->getFieldCount();
//     }
//     return 0;
// }

// const char* vanetza__security__EcdsaSignatureDescriptor::getFieldName(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldName(field);
//         field -= basedesc->getFieldCount();
//     }
//     return nullptr;
// }

// int vanetza__security__EcdsaSignatureDescriptor::findField(const char* fieldName) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     return basedesc ? basedesc->findField(fieldName) : -1;
// }

// const char* vanetza__security__EcdsaSignatureDescriptor::getFieldTypeString(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldTypeString(field);
//         field -= basedesc->getFieldCount();
//     }
//     return nullptr;
// }

// const char** vanetza__security__EcdsaSignatureDescriptor::getFieldPropertyNames(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldPropertyNames(field);
//         field -= basedesc->getFieldCount();
//     }
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

// const char* vanetza__security__EcdsaSignatureDescriptor::getFieldProperty(int field, const char* propertyname) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldProperty(field, propertyname);
//         field -= basedesc->getFieldCount();
//     }
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

// int vanetza__security__EcdsaSignatureDescriptor::getFieldArraySize(void* object, int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldArraySize(object, field);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return 0;
//     }
// }

// const char* vanetza__security__EcdsaSignatureDescriptor::getFieldDynamicTypeString(void* object, int field, int i) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldDynamicTypeString(object, field, i);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

// std::string vanetza__security__EcdsaSignatureDescriptor::getFieldValueAsString(void* object, int field, int i) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldValueAsString(object, field, i);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return "";
//     }
// }

// bool vanetza__security__EcdsaSignatureDescriptor::setFieldValueAsString(void* object, int field, int i, const char* value) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->setFieldValueAsString(object, field, i, value);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return false;
//     }
// }

// const char* vanetza__security__EcdsaSignatureDescriptor::getFieldStructName(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldStructName(field);
//         field -= basedesc->getFieldCount();
//     }
//     return nullptr;
// }

// void* vanetza__security__EcdsaSignatureDescriptor::getFieldStructValuePointer(void* object, int field, int i) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldStructValuePointer(object, field, i);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::EcdsaSignature* pp = (vanetza::security::EcdsaSignature*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

// // class vanetza__security__CertificateDescriptor : public omnetpp::cClassDescriptor
// // {
// // private:
// //     mutable const char** propertynames;

// // public:
// //     vanetza__security__CertificateDescriptor();
// //     virtual ~vanetza__security__CertificateDescriptor();

// //     virtual bool doesSupport(omnetpp::cObject* obj) const override;
// //     virtual const char** getPropertyNames() const override;
// //     virtual const char* getProperty(const char* propertyname) const override;
// //     virtual int getFieldCount() const override;
// //     virtual const char* getFieldName(int field) const override;
// //     virtual int findField(const char* fieldName) const override;
// //     virtual unsigned int getFieldTypeFlags(int field) const override;
// //     virtual const char* getFieldTypeString(int field) const override;
// //     virtual const char** getFieldPropertyNames(int field) const override;
// //     virtual const char* getFieldProperty(int field, const char* propertyname) const override;
// //     virtual int getFieldArraySize(void* object, int field) const override;

// //     virtual const char* getFieldDynamicTypeString(void* object, int field, int i) const override;
// //     virtual std::string getFieldValueAsString(void* object, int field, int i) const override;
// //     virtual bool setFieldValueAsString(void* object, int field, int i, const char* value) const override;

// //     virtual const char* getFieldStructName(int field) const override;
// //     virtual void* getFieldStructValuePointer(void* object, int field, int i) const override;
// // };

// Register_ClassDescriptor(vanetza__security__CertificateDescriptor)

//     vanetza__security__CertificateDescriptor::vanetza__security__CertificateDescriptor() :
//     omnetpp::cClassDescriptor("vanetza::security::Certificate", "omnetpp::cObject")
// {
//     propertynames = nullptr;
// }

// vanetza__security__CertificateDescriptor::~vanetza__security__CertificateDescriptor()
// {
//     delete[] propertynames;
// }

// bool vanetza__security__CertificateDescriptor::doesSupport(omnetpp::cObject* obj) const
// {
//     return dynamic_cast<vanetza::security::Certificate*>(obj) != nullptr;
// }

// const char** vanetza__security__CertificateDescriptor::getPropertyNames() const
// {
//     if (!propertynames) {
//         static const char* names[] = {"existingClass", nullptr};
//         omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//         const char** basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
//         propertynames = mergeLists(basenames, names);
//     }
//     return propertynames;
// }

// const char* vanetza__security__CertificateDescriptor::getProperty(const char* propertyname) const
// {
//     if (!strcmp(propertyname, "existingClass"))
//         return "";
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     return basedesc ? basedesc->getProperty(propertyname) : nullptr;
// }

// int vanetza__security__CertificateDescriptor::getFieldCount() const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     return basedesc ? 0 + basedesc->getFieldCount() : 0;
// }

// unsigned int vanetza__security__CertificateDescriptor::getFieldTypeFlags(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldTypeFlags(field);
//         field -= basedesc->getFieldCount();
//     }
//     return 0;
// }

// const char* vanetza__security__CertificateDescriptor::getFieldName(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldName(field);
//         field -= basedesc->getFieldCount();
//     }
//     return nullptr;
// }

// int vanetza__security__CertificateDescriptor::findField(const char* fieldName) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     return basedesc ? basedesc->findField(fieldName) : -1;
// }

// const char* vanetza__security__CertificateDescriptor::getFieldTypeString(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldTypeString(field);
//         field -= basedesc->getFieldCount();
//     }
//     return nullptr;
// }

// const char** vanetza__security__CertificateDescriptor::getFieldPropertyNames(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldPropertyNames(field);
//         field -= basedesc->getFieldCount();
//     }
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

// const char* vanetza__security__CertificateDescriptor::getFieldProperty(int field, const char* propertyname) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldProperty(field, propertyname);
//         field -= basedesc->getFieldCount();
//     }
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

// int vanetza__security__CertificateDescriptor::getFieldArraySize(void* object, int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldArraySize(object, field);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return 0;
//     }
// }

// const char* vanetza__security__CertificateDescriptor::getFieldDynamicTypeString(void* object, int field, int i) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldDynamicTypeString(object, field, i);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

// std::string vanetza__security__CertificateDescriptor::getFieldValueAsString(void* object, int field, int i) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldValueAsString(object, field, i);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return "";
//     }
// }

// bool vanetza__security__CertificateDescriptor::setFieldValueAsString(void* object, int field, int i, const char* value) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->setFieldValueAsString(object, field, i, value);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return false;
//     }
// }

// const char* vanetza__security__CertificateDescriptor::getFieldStructName(int field) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldStructName(field);
//         field -= basedesc->getFieldCount();
//     }
//     return nullptr;
// }

// void* vanetza__security__CertificateDescriptor::getFieldStructValuePointer(void* object, int field, int i) const
// {
//     omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
//     if (basedesc) {
//         if (field < basedesc->getFieldCount())
//             return basedesc->getFieldStructValuePointer(object, field, i);
//         field -= basedesc->getFieldCount();
//     }
//     vanetza::security::Certificate* pp = (vanetza::security::Certificate*)object;
//     (void)pp;
//     switch (field) {
//         default:
//             return nullptr;
//     }
// }

Register_Class(V2VMessage)

V2VMessage::V2VMessage(const char* name, short kind) : ::omnetpp::cPacket(name, kind)
{
    this->timestamp = 0;
}

V2VMessage::V2VMessage(const V2VMessage& other) : ::omnetpp::cPacket(other)
{
    copy(other);
}

V2VMessage::~V2VMessage()
{
}

V2VMessage& V2VMessage::operator=(const V2VMessage& other)
{
    if (this == &other)
        return *this;
    ::omnetpp::cPacket::operator=(other);
    copy(other);
    return *this;
}

void V2VMessage::copy(const V2VMessage& other)
{
    this->timestamp = other.timestamp;
    this->certificate = other.certificate;
    this->signature = other.signature;
    this->payload = other.payload;
}

void V2VMessage::parsimPack(omnetpp::cCommBuffer* b) const
{
    ::omnetpp::cPacket::parsimPack(b);
    doParsimPacking(b, this->timestamp);
    doParsimPacking(b, this->certificate);
    doParsimPacking(b, this->signature);
    doParsimPacking(b, this->payload);
}

void V2VMessage::parsimUnpack(omnetpp::cCommBuffer* b)
{
    ::omnetpp::cPacket::parsimUnpack(b);
    doParsimUnpacking(b, this->timestamp);
    doParsimUnpacking(b, this->certificate);
    doParsimUnpacking(b, this->signature);
    doParsimUnpacking(b, this->payload);
}

::omnetpp::simtime_t V2VMessage::getTimestamp() const
{
    return this->timestamp;
}

void V2VMessage::setTimestamp(::omnetpp::simtime_t timestamp)
{
    this->timestamp = timestamp;
}

vanetza::security::Certificate& V2VMessage::getCertificate()
{
    return this->certificate;
}

void V2VMessage::setCertificate(const vanetza::security::Certificate& certificate)
{
    this->certificate = certificate;
}

vanetza::security::EcdsaSignature& V2VMessage::getSignature()
{
    return this->signature;
}

void V2VMessage::setSignature(const vanetza::security::EcdsaSignature& signature)
{
    this->signature = signature;
}

const char* V2VMessage::getPayload() const
{
    return this->payload.c_str();
}

void V2VMessage::setPayload(const char* payload)
{
    this->payload = payload;
}

class V2VMessageDescriptor : public omnetpp::cClassDescriptor
{
private:
    mutable const char** propertynames;

public:
    V2VMessageDescriptor();
    virtual ~V2VMessageDescriptor();

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

Register_ClassDescriptor(V2VMessageDescriptor)

    V2VMessageDescriptor::V2VMessageDescriptor() :
    omnetpp::cClassDescriptor("V2VMessage", "omnetpp::cPacket")
{
    propertynames = nullptr;
}

V2VMessageDescriptor::~V2VMessageDescriptor()
{
    delete[] propertynames;
}

bool V2VMessageDescriptor::doesSupport(omnetpp::cObject* obj) const
{
    return dynamic_cast<V2VMessage*>(obj) != nullptr;
}

const char** V2VMessageDescriptor::getPropertyNames() const
{
    if (!propertynames) {
        static const char* names[] = {nullptr};
        omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
        const char** basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
        propertynames = mergeLists(basenames, names);
    }
    return propertynames;
}

const char* V2VMessageDescriptor::getProperty(const char* propertyname) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : nullptr;
}

int V2VMessageDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    return basedesc ? 4 + basedesc->getFieldCount() : 4;
}

unsigned int V2VMessageDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeFlags(field);
        field -= basedesc->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        FD_ISEDITABLE,
        FD_ISCOMPOUND | FD_ISCOBJECT,
        FD_ISCOMPOUND | FD_ISCOBJECT,
        FD_ISEDITABLE,
    };
    return (field >= 0 && field < 4) ? fieldTypeFlags[field] : 0;
}

const char* V2VMessageDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldName(field);
        field -= basedesc->getFieldCount();
    }
    static const char* fieldNames[] = {
        "timestamp",
        "certificate",
        "signature",
        "payload",
    };
    return (field >= 0 && field < 4) ? fieldNames[field] : nullptr;
}

int V2VMessageDescriptor::findField(const char* fieldName) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    int base = basedesc ? basedesc->getFieldCount() : 0;
    if (fieldName[0] == 't' && strcmp(fieldName, "timestamp") == 0)
        return base + 0;
    if (fieldName[0] == 'c' && strcmp(fieldName, "certificate") == 0)
        return base + 1;
    if (fieldName[0] == 's' && strcmp(fieldName, "signature") == 0)
        return base + 2;
    if (fieldName[0] == 'p' && strcmp(fieldName, "payload") == 0)
        return base + 3;
    return basedesc ? basedesc->findField(fieldName) : -1;
}

const char* V2VMessageDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeString(field);
        field -= basedesc->getFieldCount();
    }
    static const char* fieldTypeStrings[] = {
        "simtime_t",
        "vanetza::security::Certificate",
        "vanetza::security::EcdsaSignature",
        "string",
    };
    return (field >= 0 && field < 4) ? fieldTypeStrings[field] : nullptr;
}

const char** V2VMessageDescriptor::getFieldPropertyNames(int field) const
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

const char* V2VMessageDescriptor::getFieldProperty(int field, const char* propertyname) const
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

int V2VMessageDescriptor::getFieldArraySize(void* object, int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldArraySize(object, field);
        field -= basedesc->getFieldCount();
    }
    V2VMessage* pp = (V2VMessage*)object;
    (void)pp;
    switch (field) {
        default:
            return 0;
    }
}

const char* V2VMessageDescriptor::getFieldDynamicTypeString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldDynamicTypeString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    V2VMessage* pp = (V2VMessage*)object;
    (void)pp;
    switch (field) {
        default:
            return nullptr;
    }
}

std::string V2VMessageDescriptor::getFieldValueAsString(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldValueAsString(object, field, i);
        field -= basedesc->getFieldCount();
    }
    V2VMessage* pp = (V2VMessage*)object;
    (void)pp;
    switch (field) {
        case 0:
            return simtime2string(pp->getTimestamp());
        case 1: {
            std::stringstream out;
            out << pp->getCertificate();
            return out.str();
        }
        case 2: {
            std::stringstream out;
            out << pp->getSignature();
            return out.str();
        }
        case 3:
            return oppstring2string(pp->getPayload());
        default:
            return "";
    }
}

bool V2VMessageDescriptor::setFieldValueAsString(void* object, int field, int i, const char* value) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->setFieldValueAsString(object, field, i, value);
        field -= basedesc->getFieldCount();
    }
    V2VMessage* pp = (V2VMessage*)object;
    (void)pp;
    switch (field) {
        case 0:
            pp->setTimestamp(string2simtime(value));
            return true;
        case 3:
            pp->setPayload((value));
            return true;
        default:
            return false;
    }
}

const char* V2VMessageDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructName(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        case 1:
            return omnetpp::opp_typename(typeid(vanetza::security::Certificate));
        case 2:
            return omnetpp::opp_typename(typeid(vanetza::security::EcdsaSignature));
        default:
            return nullptr;
    };
}

void* V2VMessageDescriptor::getFieldStructValuePointer(void* object, int field, int i) const
{
    omnetpp::cClassDescriptor* basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructValuePointer(object, field, i);
        field -= basedesc->getFieldCount();
    }
    V2VMessage* pp = (V2VMessage*)object;
    (void)pp;
    switch (field) {
        case 1:
            return (void*)(&pp->getCertificate());
            break;
        case 2:
            return (void*)(&pp->getSignature());
            break;
        default:
            return nullptr;
    }
}

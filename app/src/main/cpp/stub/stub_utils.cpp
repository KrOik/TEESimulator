#include "utils/RefBase.h"
#include "utils/String16.h"
#include "utils/String8.h"
#include "utils/StrongPointer.h"

#include <cstdio>
#include <cstdlib>

namespace android {

namespace {
class StubWeakRef : public RefBase::weakref_type {
public:
    RefBase *refBase() const override { return nullptr; }
    void incWeak(const void *) override {}
    void incWeakRequireWeak(const void *) override {}
    void decWeak(const void *) override {}
    bool attemptIncStrong(const void *) override { return false; }
    bool attemptIncWeak(const void *) override { return false; }
};

static StubWeakRef g_stub_weak_ref;
}

void RefBase::incStrong(const void *id) const {}

void RefBase::incStrongRequireStrong(const void *id) const {}

void RefBase::decStrong(const void *id) const {}

void RefBase::forceIncStrong(const void *id) const {}

RefBase::weakref_type *RefBase::createWeak(const void *id) const {
    fprintf(stderr, "WARNING: RefBase::createWeak() called in stub implementation - returning safe stub weakref\n");
    return &g_stub_weak_ref;
}

RefBase::weakref_type *RefBase::getWeakRefs() const {
    fprintf(stderr, "WARNING: RefBase::getWeakRefs() called in stub implementation - returning safe stub weakref\n");
    return &g_stub_weak_ref;
}

RefBase::RefBase() : mRefs(nullptr) {}
RefBase::~RefBase() {}

void RefBase::onFirstRef() {}
void RefBase::onLastStrongRef(const void *id) {}
bool RefBase::onIncStrongAttempted(uint32_t flags, const void *id) {
    return false;
}
void RefBase::onLastWeakRef(const void *id) {}

RefBase *RefBase::weakref_type::refBase() const {
    return nullptr;
}

void RefBase::weakref_type::incWeak(const void *id) {}
void RefBase::weakref_type::incWeakRequireWeak(const void *id) {}
void RefBase::weakref_type::decWeak(const void *id) {}

bool RefBase::weakref_type::attemptIncStrong(const void *id) {
    return false;
}

bool RefBase::weakref_type::attemptIncWeak(const void *id) {
    return false;
}

void sp_report_race() {}

String8::String8() {}

String16::String16() {}

String16::String16(const String16 &o) {}

String16::String16(String16 &&o) noexcept {}

String16::String16(const char *o) {
    if (!o) {
        fprintf(stderr, "WARNING: String16 constructed with null pointer\n");
    }
}

String16::~String16() {}
}
void RefBase::onLastWeakRef(const void *id) {}

RefBase *RefBase::weakref_type::refBase() const {
    return nullptr;
}

void RefBase::weakref_type::incWeak(const void *id) {}
void RefBase::weakref_type::incWeakRequireWeak(const void *id) {}
void RefBase::weakref_type::decWeak(const void *id) {}

bool RefBase::weakref_type::attemptIncStrong(const void *id) {
    return false;
}

bool RefBase::weakref_type::attemptIncWeak(const void *id) {
    return false;
}

void sp_report_race() {}

String8::String8() {}

String16::String16() {}

String16::String16(const String16 &o) {}

String16::String16(String16 &&o) noexcept {}

String16::String16(const char *o) {}

String16::~String16() {}
} // namespace android

#pragma once

#include <windows.h>
#include <array>
#include <cstddef>
#include <cstdint>

namespace wesplab::abi_0_1_0_156346177 {

inline constexpr wchar_t kExpectedVersion[] = L"0.1.0.156346177";
inline constexpr std::uint32_t kProcessCreateEvent = 1000;
inline constexpr std::uint32_t kProcessCommandLine = 1;
inline constexpr std::uint32_t kProcessId = 6;
inline constexpr std::uint32_t kProcessImagePath = 20;

using OpaqueHandle = void*;
using NotificationCallback = void(WINAPI*)(void* notification, void* context);

struct ClientDescriptor {
    GUID id;
    const wchar_t* name;
    const wchar_t* altitude;
};

struct EventQueueDescriptor {
    GUID id;
    std::uint32_t version;
    std::uint32_t type;
    std::uint32_t capacity;
    std::uint32_t format;
};

struct alignas(8) ProcessCreateConfig {
    std::uint32_t mask;
    std::array<std::byte, 0x2c> reserved_04;
    std::uint32_t property_count;
    std::uint32_t reserved_34;
    const std::uint32_t* property_ids;
    std::array<std::byte, 0x4f0> reserved_40;
};

struct RuleDescriptor {
    GUID id;
    std::uint64_t order_group;
    std::uint32_t lifetime;
    std::uint32_t reserved_1c;
    std::uint32_t event_type;
    std::array<std::byte, 0x3c> reserved_24;
    const ProcessCreateConfig* event_config;
    std::array<std::byte, 0x3d8> reserved_68;
    std::uint32_t modification;
    std::array<std::byte, 0x0c> reserved_444;
    std::uint32_t action;
    std::uint32_t reserved_454;
    OpaqueHandle action_object;
    std::uint64_t reserved_460;
};

struct RuleUpdate {
    std::uint32_t operation;
    std::uint32_t reserved_04;
    OpaqueHandle rule;
    std::uint64_t reserved_10;
};

struct EventDataPrefix {
    std::uint64_t instance_id;
    GUID rule_id;
    std::array<std::byte, 0x60> reserved_18;
    std::uint32_t event_type;
    std::uint32_t reserved_7c;
};

struct NotificationHeader {
    GUID queue_id;
    std::uint32_t reserved_10;
    std::uint32_t reserved_14;
    const EventDataPrefix* data;
    std::array<std::byte, 0x28> reserved_20;
    std::uint32_t external_size;
    std::uint32_t reserved_4c;
    void* owner;
    const void* external_payload;
    std::array<std::byte, 0x10> reserved_60;
};

struct Property {
    std::uint32_t id;
    std::uint32_t type;
    std::uint64_t value;
};

static_assert(sizeof(void*) == 8, "WESP sample ABI is 64-bit only");
static_assert(sizeof(ClientDescriptor) == 0x20);
static_assert(sizeof(EventQueueDescriptor) == 0x20);
static_assert(sizeof(ProcessCreateConfig) == 0x530);
static_assert(offsetof(ProcessCreateConfig, property_count) == 0x30);
static_assert(offsetof(ProcessCreateConfig, property_ids) == 0x38);
static_assert(sizeof(RuleDescriptor) == 0x468);
static_assert(offsetof(RuleDescriptor, event_config) == 0x60);
static_assert(offsetof(RuleDescriptor, modification) == 0x440);
static_assert(offsetof(RuleDescriptor, action) == 0x450);
static_assert(offsetof(RuleDescriptor, action_object) == 0x458);
static_assert(sizeof(RuleUpdate) == 0x18);
static_assert(sizeof(EventDataPrefix) == 0x80);
static_assert(sizeof(NotificationHeader) == 0x70);
static_assert(sizeof(Property) == 0x10);

}  // namespace wesplab::abi_0_1_0_156346177

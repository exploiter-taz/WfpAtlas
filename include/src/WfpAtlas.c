#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <ole2.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ole32.lib")

typedef struct {
    GUID        guid;
    const char *name;
    const char *why;
} EDR_LAYER;

#define DEFINE_GUID_LOCAL(name, l, w1, w2, b1,b2,b3,b4,b5,b6,b7,b8) \
    static const GUID name = { l, w1, w2, { b1,b2,b3,b4,b5,b6,b7,b8 } }

DEFINE_GUID_LOCAL(GUID_ALE_AUTH_CONNECT_V4,
    0xc38d57d1,0x05a7,0x4c33, 0x90,0x4f,0x7f,0xbc,0xee,0xe6,0x0e,0x82);
DEFINE_GUID_LOCAL(GUID_ALE_AUTH_CONNECT_V6,
    0x4a72393b,0x319f,0x44bc, 0x84,0xc3,0xba,0x54,0xdc,0xb3,0xb6,0xb4);
DEFINE_GUID_LOCAL(GUID_ALE_AUTH_RECV_ACCEPT_V4,
    0xe1cd9fe7,0xf4b5,0x4273, 0x96,0xc0,0x59,0x2e,0x48,0x7b,0x86,0x50);
DEFINE_GUID_LOCAL(GUID_ALE_AUTH_RECV_ACCEPT_V6,
    0x4b46bf0a,0x4523,0x4e57, 0xaa,0x38,0xa9,0x87,0xbf,0xf5,0x8a,0xb2);
DEFINE_GUID_LOCAL(GUID_ALE_FLOW_ESTABLISHED_V4,
    0xaf80470a,0x5596,0x4c13, 0x99,0x92,0x53,0x9e,0x6f,0xe5,0x79,0x67);
DEFINE_GUID_LOCAL(GUID_ALE_FLOW_ESTABLISHED_V6,
    0x0fdc7d2a,0xbe37,0x4ac3, 0xbf,0x83,0x93,0x53,0xa1,0x0e,0x43,0x41);
DEFINE_GUID_LOCAL(GUID_DATAGRAM_DATA_V4,
    0x3d08bf4e,0x45f6,0x4930, 0xa9,0x22,0x41,0x70,0x98,0xe2,0x00,0x27);
DEFINE_GUID_LOCAL(GUID_DATAGRAM_DATA_V6,
    0xf2c809c7,0x85a3,0x4ab6, 0xa8,0x5a,0xdc,0x4f,0x17,0xe7,0xd1,0x8a);
DEFINE_GUID_LOCAL(GUID_STREAM_V4,
    0x3b2b46d5,0x3f5f,0x4fc3, 0xa7,0xa4,0x19,0xa7,0x2a,0x01,0x4f,0x37);
DEFINE_GUID_LOCAL(GUID_STREAM_V6,
    0x5de48536,0xa90f,0x4874, 0x84,0x59,0x32,0x73,0x3c,0x65,0x01,0x5c);
DEFINE_GUID_LOCAL(GUID_INBOUND_TRANSPORT_V4,
    0x5926dfc8,0xe3cf,0x4426, 0xa2,0x83,0xdc,0x39,0x37,0x38,0x9c,0x3e);
DEFINE_GUID_LOCAL(GUID_INBOUND_TRANSPORT_V6,
    0xf52032cb,0x991c,0x46e7, 0x97,0x1d,0x26,0x01,0x45,0x9a,0x91,0xca);
DEFINE_GUID_LOCAL(GUID_OUTBOUND_TRANSPORT_V4,
    0x09e61aea,0xd214,0x46e2, 0x9b,0x21,0xb2,0x6b,0x0b,0x2f,0x28,0xc8);
DEFINE_GUID_LOCAL(GUID_OUTBOUND_TRANSPORT_V6,
    0xe1735bde,0x013f,0x4655, 0xb3,0x51,0xa4,0x9e,0x15,0x76,0x2d,0xf0);
DEFINE_GUID_LOCAL(GUID_ALE_RESOURCE_ASSIGNMENT_V4,
    0x1247d66d,0x0b60,0x4a75, 0x82,0xf1,0xd2,0x14,0xbc,0x98,0x64,0xf7);
DEFINE_GUID_LOCAL(GUID_ALE_RESOURCE_ASSIGNMENT_V6,
    0x55a650e1,0x5f0a,0x4eca, 0xa6,0x53,0x88,0xf5,0x3b,0x26,0xaa,0x8c);

static const EDR_LAYER g_EdrLayers[] = {
    { {0xc38d57d1,0x05a7,0x4c33,{0x90,0x4f,0x7f,0xbc,0xee,0xe6,0x0e,0x82}},
      "ALE_AUTH_CONNECT_V4", "outbound connection decisions (IPv4)" },
    { {0x4a72393b,0x319f,0x44bc,{0x84,0xc3,0xba,0x54,0xdc,0xb3,0xb6,0xb4}},
      "ALE_AUTH_CONNECT_V6", "outbound connection decisions (IPv6)" },
    { {0xe1cd9fe7,0xf4b5,0x4273,{0x96,0xc0,0x59,0x2e,0x48,0x7b,0x86,0x50}},
      "ALE_AUTH_RECV_ACCEPT_V4", "inbound connection decisions (IPv4)" },
    { {0x4b46bf0a,0x4523,0x4e57,{0xaa,0x38,0xa9,0x87,0xbf,0xf5,0x8a,0xb2}},
      "ALE_AUTH_RECV_ACCEPT_V6", "inbound connection decisions (IPv6)" },
    { {0xaf80470a,0x5596,0x4c13,{0x99,0x92,0x53,0x9e,0x6f,0xe5,0x79,0x67}},
      "ALE_FLOW_ESTABLISHED_V4", "per-flow context (IPv4)" },
    { {0x0fdc7d2a,0xbe37,0x4ac3,{0xbf,0x83,0x93,0x53,0xa1,0x0e,0x43,0x41}},
      "ALE_FLOW_ESTABLISHED_V6", "per-flow context (IPv6)" },
    { {0x3d08bf4e,0x45f6,0x4930,{0xa9,0x22,0x41,0x70,0x98,0xe2,0x00,0x27}},
      "DATAGRAM_DATA_V4", "UDP payload inspection (DNS/QUIC/etc.) IPv4" },
    { {0xf2c809c7,0x85a3,0x4ab6,{0xa8,0x5a,0xdc,0x4f,0x17,0xe7,0xd1,0x8a}},
      "DATAGRAM_DATA_V6", "UDP payload inspection (DNS/QUIC/etc.) IPv6" },
    { {0x3b2b46d5,0x3f5f,0x4fc3,{0xa7,0xa4,0x19,0xa7,0x2a,0x01,0x4f,0x37}},
      "STREAM_V4", "TCP stream content (TLS fingerprinting) IPv4" },
    { {0x5de48536,0xa90f,0x4874,{0x84,0x59,0x32,0x73,0x3c,0x65,0x01,0x5c}},
      "STREAM_V6", "TCP stream content (TLS fingerprinting) IPv6" },
    { {0x5926dfc8,0xe3cf,0x4426,{0xa2,0x83,0xdc,0x39,0x37,0x38,0x9c,0x3e}},
      "INBOUND_TRANSPORT_V4", "raw inbound transport packets (IPv4)" },
    { {0xf52032cb,0x991c,0x46e7,{0x97,0x1d,0x26,0x01,0x45,0x9a,0x91,0xca}},
      "INBOUND_TRANSPORT_V6", "raw inbound transport packets (IPv6)" },
    { {0x09e61aea,0xd214,0x46e2,{0x9b,0x21,0xb2,0x6b,0x0b,0x2f,0x28,0xc8}},
      "OUTBOUND_TRANSPORT_V4", "raw outbound transport packets (IPv4)" },
    { {0xe1735bde,0x013f,0x4655,{0xb3,0x51,0xa4,0x9e,0x15,0x76,0x2d,0xf0}},
      "OUTBOUND_TRANSPORT_V6", "raw outbound transport packets (IPv6)" },
    { {0x1247d66d,0x0b60,0x4a75,{0x82,0xf1,0xd2,0x14,0xbc,0x98,0x64,0xf7}},
      "ALE_RESOURCE_ASSIGNMENT_V4", "process binds to a local port (IPv4)" },
    { {0x55a650e1,0x5f0a,0x4eca,{0xa6,0x53,0x88,0xf5,0x3b,0x26,0xaa,0x8c}},
      "ALE_RESOURCE_ASSIGNMENT_V6", "process binds to a local port (IPv6)" },
    { {0xc86fd1bf,0x21cd,0x497e,{0xa0,0xbb,0x17,0x42,0x5c,0x88,0x5c,0x58}},
      "INBOUND_IPPACKET_V4", "raw inbound IP packet before transport parsing (IPv4)" },
    { {0xf52032cb,0x991c,0x46e7,{0x97,0x1d,0x26,0x01,0x45,0x9a,0x91,0xca}},
      "INBOUND_IPPACKET_V6", "raw inbound IP packet before transport parsing (IPv6)" },
    { {0x1e5c9fae,0x8a84,0x4135,{0xa3,0x31,0x95,0x0b,0x54,0x22,0x9e,0xcd}},
      "OUTBOUND_IPPACKET_V4", "raw outbound IP packet after transport, before NIC (IPv4)" },
    { {0xa3b3ab6b,0x3564,0x488c,{0x91,0x17,0x52,0x3d,0x6e,0x28,0x8b,0xf2}},
      "OUTBOUND_IPPACKET_V6", "raw outbound IP packet after transport, before NIC (IPv6)" },
};

#define EDR_LAYER_COUNT  (sizeof(g_EdrLayers) / sizeof(g_EdrLayers[0]))

static void
GuidToStr(_In_ const GUID *g, _Out_writes_(39) wchar_t *buf)
{
    StringFromGUID2(g, buf, 39);
}

static void
GuidToStrA(_In_ const GUID *g, _Out_writes_(39) char *buf)
{
    wchar_t tmp[39];
    StringFromGUID2(g, tmp, 39);
    WideCharToMultiByte(CP_ACP, 0, tmp, -1, buf, 39, NULL, NULL);
}

static void
PrintSeparator(void)
{
    printf("------------------------------------------------------------------------\n");
}

static const EDR_LAYER *
LookupEdrLayer(_In_ const GUID *layerGuid)
{
    UINT32 i;
    for (i = 0; i < EDR_LAYER_COUNT; i++) {
        if (IsEqualGUID(layerGuid, &g_EdrLayers[i].guid))
            return &g_EdrLayers[i];
    }
    return NULL;
}

static void
XmlEscape(_In_ const wchar_t *src, _Out_ char *dst, size_t dstLen)
{
    size_t out = 0;
    while (*src && out + 8 < dstLen) {
        wchar_t c = *src++;
        if (c == L'<')       { memcpy(dst+out, "&lt;",   4); out += 4; }
        else if (c == L'>')  { memcpy(dst+out, "&gt;",   4); out += 4; }
        else if (c == L'&')  { memcpy(dst+out, "&amp;",  5); out += 5; }
        else if (c == L'"')  { memcpy(dst+out, "&quot;", 6); out += 6; }
        else if (c < 0x80)   { dst[out++] = (char)c; }
        else                 { dst[out++] = '?'; }
    }
    dst[out] = '\0';
}

static void
EnumerateProviders(_In_ HANDLE engine)
{
    FWPM_PROVIDER0 **providers = NULL;
    UINT32           count     = 0;
    DWORD            result;
    UINT32           i;
    wchar_t          guidStr[39];
    HANDLE           enumHandle = NULL;

    printf("\n");
    PrintSeparator();
    printf("  Providers\n");
    PrintSeparator();

    result = FwpmProviderCreateEnumHandle0(engine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to open provider enum handle: 0x%08X\n", result);
        return;
    }

    result = FwpmProviderEnum0(engine, enumHandle, 0xFFFFFFFF, &providers, &count);
    FwpmProviderDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to enumerate providers: 0x%08X\n", result);
        return;
    }

    if (count == 0)
        printf("  (none)\n");

    for (i = 0; i < count; i++) {
        FWPM_PROVIDER0 *p = providers[i];
        GuidToStr(&p->providerKey, guidStr);

        printf("  [%u] GUID   : %ls\n", i, guidStr);
        printf("       Name   : %ls\n",
               p->displayData.name ? p->displayData.name : L"<none>");
        printf("       Desc   : %ls\n",
               p->displayData.description ? p->displayData.description : L"<none>");
        printf("       Flags  : 0x%08X%s\n", p->flags,
               (p->flags & FWPM_PROVIDER_FLAG_PERSISTENT) ? "  [PERSISTENT]" : "");
        printf("\n");
    }

    printf("  Total providers: %u\n", count);
    FwpmFreeMemory0((void **)&providers);
}

static void
EnumerateSubLayers(_In_ HANDLE engine)
{
    FWPM_SUBLAYER0 **subLayers = NULL;
    UINT32           count     = 0;
    DWORD            result;
    UINT32           i;
    wchar_t          guidStr[39];
    wchar_t          provGuidStr[39];
    HANDLE           enumHandle = NULL;

    printf("\n");
    PrintSeparator();
    printf("  Sublayers\n");
    PrintSeparator();

    result = FwpmSubLayerCreateEnumHandle0(engine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to open sublayer enum handle: 0x%08X\n", result);
        return;
    }

    result = FwpmSubLayerEnum0(engine, enumHandle, 0xFFFFFFFF, &subLayers, &count);
    FwpmSubLayerDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to enumerate sublayers: 0x%08X\n", result);
        return;
    }

    if (count == 0)
        printf("  (none)\n");

    for (i = 0; i < count; i++) {
        FWPM_SUBLAYER0 *s = subLayers[i];
        GuidToStr(&s->subLayerKey, guidStr);
        if (s->providerKey)
            GuidToStr(s->providerKey, provGuidStr);
        else
            wcscpy_s(provGuidStr, 39, L"<none>");

        printf("  [%u] GUID     : %ls\n", i, guidStr);
        printf("       Name     : %ls\n",
               s->displayData.name ? s->displayData.name : L"<none>");
        printf("       Weight   : 0x%04X\n", s->weight);
        printf("       Provider : %ls\n", provGuidStr);
        printf("       Flags    : 0x%08X%s\n", s->flags,
               (s->flags & FWPM_SUBLAYER_FLAG_PERSISTENT) ? "  [PERSISTENT]" : "");
        printf("\n");
    }

    printf("  Total sublayers: %u\n", count);
    FwpmFreeMemory0((void **)&subLayers);
}

static void
EnumerateCallouts(_In_ HANDLE engine)
{
    FWPM_CALLOUT0 **callouts = NULL;
    UINT32          count    = 0;
    DWORD           result;
    UINT32          i;
    wchar_t         guidStr[39];
    wchar_t         layerStr[39];
    wchar_t         provGuidStr[39];
    HANDLE          enumHandle = NULL;

    printf("\n");
    PrintSeparator();
    printf("  Callouts\n");
    PrintSeparator();

    result = FwpmCalloutCreateEnumHandle0(engine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to open callout enum handle: 0x%08X\n", result);
        return;
    }

    result = FwpmCalloutEnum0(engine, enumHandle, 0xFFFFFFFF, &callouts, &count);
    FwpmCalloutDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to enumerate callouts: 0x%08X\n", result);
        return;
    }

    if (count == 0)
        printf("  (none)\n");

    for (i = 0; i < count; i++) {
        FWPM_CALLOUT0 *c = callouts[i];
        const EDR_LAYER *edr = LookupEdrLayer(&c->applicableLayer);

        GuidToStr(&c->calloutKey, guidStr);
        GuidToStr(&c->applicableLayer, layerStr);
        if (c->providerKey)
            GuidToStr(c->providerKey, provGuidStr);
        else
            wcscpy_s(provGuidStr, 39, L"<none>");

        printf("  [%u] GUID     : %ls\n", i, guidStr);
        printf("       Name     : %ls\n",
               c->displayData.name ? c->displayData.name : L"<none>");
        printf("       Desc     : %ls\n",
               c->displayData.description ? c->displayData.description : L"<none>");
        if (edr)
            printf("       Layer    : %s  [!] %s\n", edr->name, edr->why);
        else
            printf("       Layer    : %ls\n", layerStr);
        printf("       Provider : %ls\n", provGuidStr);
        printf("       Flags    : 0x%08X%s\n", c->flags,
               (c->flags & FWPM_CALLOUT_FLAG_PERSISTENT) ? "  [PERSISTENT]" : "");
        printf("\n");
    }

    printf("  Total callouts: %u\n", count);
    FwpmFreeMemory0((void **)&callouts);
}

static void
EnumerateFilters(_In_ HANDLE engine)
{
    FWPM_FILTER0 **filters = NULL;
    UINT32         count   = 0;
    DWORD          result;
    UINT32         i, j;
    wchar_t        guidStr[39];
    wchar_t        layerStr[39];
    wchar_t        calloutStr[39];
    HANDLE         enumHandle = NULL;

    static const struct { UINT32 type; const char *name; } actionNames[] = {
        { FWP_ACTION_BLOCK,               "BLOCK"               },
        { FWP_ACTION_PERMIT,              "PERMIT"              },
        { FWP_ACTION_CALLOUT_TERMINATING, "CALLOUT_TERMINATING" },
        { FWP_ACTION_CALLOUT_INSPECTION,  "CALLOUT_INSPECTION"  },
        { FWP_ACTION_CALLOUT_UNKNOWN,     "CALLOUT_UNKNOWN"     },
        { 0, NULL }
    };

    printf("\n");
    PrintSeparator();
    printf("  Filters\n");
    PrintSeparator();

    result = FwpmFilterCreateEnumHandle0(engine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to open filter enum handle: 0x%08X\n", result);
        return;
    }

    result = FwpmFilterEnum0(engine, enumHandle, 0xFFFFFFFF, &filters, &count);
    FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  failed to enumerate filters: 0x%08X\n", result);
        return;
    }

    if (count == 0)
        printf("  (none)\n");

    for (i = 0; i < count; i++) {
        FWPM_FILTER0 *f = filters[i];
        const char   *actionName = "UNKNOWN";
        int           k;

        GuidToStr(&f->filterKey, guidStr);
        GuidToStr(&f->layerKey,  layerStr);

        for (k = 0; actionNames[k].name != NULL; k++) {
            if ((f->action.type & 0xFF) == actionNames[k].type) {
                actionName = actionNames[k].name;
                break;
            }
        }

        printf("  [%u] FilterID  : %llu\n", i, (unsigned long long)f->filterId);
        printf("       GUID      : %ls\n", guidStr);
        printf("       Name      : %ls\n",
               f->displayData.name ? f->displayData.name : L"<none>");
        printf("       Layer     : %ls\n", layerStr);

        if (f->action.type & FWP_ACTION_FLAG_CALLOUT) {
            GuidToStr(&f->action.calloutKey, calloutStr);
            printf("       Action    : %s -> callout %ls\n", actionName, calloutStr);
        } else {
            printf("       Action    : %s\n", actionName);
        }

        if (f->weight.type == FWP_UINT8)
            printf("       Weight    : 0x%02X (uint8)\n", f->weight.uint8);
        else if (f->weight.type == FWP_UINT64 && f->weight.uint64)
            printf("       Weight    : 0x%016llX (uint64)\n",
                   (unsigned long long)*f->weight.uint64);

        if (f->numFilterConditions > 0) {
            printf("       Conditions: %u\n", f->numFilterConditions);
            for (j = 0; j < f->numFilterConditions; j++) {
                FWPM_FILTER_CONDITION0 *c = &f->filterCondition[j];
                wchar_t fieldStr[39];
                GuidToStr(&c->fieldKey, fieldStr);
                printf("         [%u] field=%ls match=%u ", j, fieldStr, c->matchType);
                switch (c->conditionValue.type) {
                case FWP_UINT8:  printf("val=%u (uint8)\n",  c->conditionValue.uint8);  break;
                case FWP_UINT16: printf("val=%u (uint16)\n", c->conditionValue.uint16); break;
                case FWP_UINT32: printf("val=0x%08X (uint32)\n", c->conditionValue.uint32); break;
                default:         printf("(type=%u)\n", c->conditionValue.type); break;
                }
            }
        }

        printf("       Flags     : 0x%08X%s%s\n", f->flags,
               (f->flags & FWPM_FILTER_FLAG_PERSISTENT) ? "  [PERSISTENT]" : "",
               (f->flags & FWPM_FILTER_FLAG_BOOTTIME)   ? "  [BOOTTIME]"   : "");
        printf("\n");
    }

    printf("  Total filters: %u\n", count);
    FwpmFreeMemory0((void **)&filters);
}

static void
ExportEdrCallouts(_In_ HANDLE engine)
{
    FWPM_CALLOUT0 **callouts    = NULL;
    UINT32          total       = 0;
    UINT32          edrCount    = 0;
    DWORD           result;
    UINT32          i;
    HANDLE          enumHandle  = NULL;
    FILE           *f           = NULL;
    char            tsBuf[64];
    time_t          now;

    result = FwpmCalloutCreateEnumHandle0(engine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  [!] ExportEdrCallouts: FwpmCalloutCreateEnumHandle0 failed: 0x%08X\n", result);
        return;
    }

    result = FwpmCalloutEnum0(engine, enumHandle, 0xFFFFFFFF, &callouts, &total);
    FwpmCalloutDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("  [!] ExportEdrCallouts: FwpmCalloutEnum0 failed: 0x%08X\n", result);
        return;
    }

    for (i = 0; i < total; i++) {
        if (LookupEdrLayer(&callouts[i]->applicableLayer))
            edrCount++;
    }

    if (fopen_s(&f, "WfpEdrCallouts.xml", "w") != 0) {
        printf("  [!] ExportEdrCallouts: cannot open WfpEdrCallouts.xml for writing\n");
        FwpmFreeMemory0((void **)&callouts);
        return;
    }

    time(&now);
    {
        struct tm tmBuf;
        gmtime_s(&tmBuf, &now);
        strftime(tsBuf, sizeof(tsBuf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf);
    }

    fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(f, "<WfpEdrCallouts\n");
    fprintf(f, "  timestamp=\"%s\"\n", tsBuf);
    fprintf(f, "  totalCallouts=\"%u\"\n", total);
    fprintf(f, "  edrCallouts=\"%u\"\n", edrCount);
    fprintf(f, "  note=\"EDR-relevant callouts only\">\n\n");

    {
        UINT32 idx = 0;
        for (i = 0; i < total; i++) {
            FWPM_CALLOUT0   *c   = callouts[i];
            const EDR_LAYER *edr = LookupEdrLayer(&c->applicableLayer);
            char  guidBuf[39], layerGuidBuf[39], provGuidBuf[39];
            char  nameBuf[512], descBuf[512];

            if (!edr)
                continue;

            GuidToStrA(&c->calloutKey,      guidBuf);
            GuidToStrA(&c->applicableLayer, layerGuidBuf);

            if (c->providerKey)
                GuidToStrA(c->providerKey, provGuidBuf);
            else
                strcpy_s(provGuidBuf, sizeof(provGuidBuf), "(none)");

            XmlEscape(c->displayData.name        ? c->displayData.name        : L"",
                      nameBuf, sizeof(nameBuf));
            XmlEscape(c->displayData.description ? c->displayData.description : L"",
                      descBuf, sizeof(descBuf));

            fprintf(f, "  <callout index=\"%u\">\n", idx++);
            fprintf(f, "    <guid>%s</guid>\n",         guidBuf);
            fprintf(f, "    <name>%s</name>\n",          nameBuf);
            fprintf(f, "    <description>%s</description>\n", descBuf);
            fprintf(f, "    <layer name=\"%s\" why=\"%s\">\n", edr->name, edr->why);
            fprintf(f, "      <guid>%s</guid>\n", layerGuidBuf);
            fprintf(f, "    </layer>\n");
            fprintf(f, "    <provider>%s</provider>\n", provGuidBuf);
            fprintf(f, "    <calloutId>%u</calloutId>\n", c->calloutId);
            fprintf(f, "    <flags value=\"0x%08X\">%s</flags>\n",
                    c->flags,
                    (c->flags & FWPM_CALLOUT_FLAG_PERSISTENT) ? "PERSISTENT" : "");
            fprintf(f, "  </callout>\n\n");
        }
    }

    fprintf(f, "</WfpEdrCallouts>\n");
    fclose(f);

    FwpmFreeMemory0((void **)&callouts);

    printf("\n");
    PrintSeparator();
    printf("  EDR callout export\n");
    PrintSeparator();
    printf("  scanned  %u callouts\n", total);
    printf("  matched  %u on EDR-relevant layers\n", edrCount);
    printf("  saved to WfpEdrCallouts.xml\n");
    PrintSeparator();
}

int
main(void)
{
    HANDLE engine = NULL;
    DWORD  result;

    printf("WfpAtlas  -  Windows Filtering Platform callout scanner\n");
    printf("Run as Administrator for complete results.\n");
    printf("\n");

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "FwpmEngineOpen0 failed: 0x%08X\n", result);
        fprintf(stderr, "Make sure you are running as Administrator.\n");
        return 1;
    }

    EnumerateProviders(engine);
    EnumerateSubLayers(engine);
    EnumerateCallouts(engine);
    EnumerateFilters(engine);
    ExportEdrCallouts(engine);

    printf("\n");
    PrintSeparator();
    printf("  done.\n");
    PrintSeparator();

    FwpmEngineClose0(engine);
    return 0;
}

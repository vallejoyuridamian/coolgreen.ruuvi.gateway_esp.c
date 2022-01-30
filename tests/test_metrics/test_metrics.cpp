/**
 * @file test_metrics.cpp
 * @author TheSomeMan
 * @date 2022-01-14
 * @copyright Ruuvi Innovations Ltd, license BSD-3-Clause.
 */

#include "metrics.h"
#include "gtest/gtest.h"
#include <string>
#include "multi_heap.h"
#include "esp_heap_caps.h"
#include "os_malloc.h"
#include "os_mutex.h"
#include "mac_addr.h"
#include "gw_mac.h"
#include "nrf52fw.h"
#include "fw_ver.h"
#include "esp_log_wrapper.hpp"

using namespace std;

class TestMetrics;

static TestMetrics *g_pTestClass;

extern "C" {

nrf52fw_version_str_t g_nrf52_firmware_version;

} // extern "C"

/*** Google-test class implementation
 * *********************************************************************************/

class MemAllocTrace
{
    vector<void *> allocated_mem;

    std::vector<void *>::iterator
    find(void *ptr)
    {
        for (auto iter = this->allocated_mem.begin(); iter != this->allocated_mem.end(); ++iter)
        {
            if (*iter == ptr)
            {
                return iter;
            }
        }
        return this->allocated_mem.end();
    }

public:
    void
    add(void *ptr)
    {
        auto iter = find(ptr);
        assert(iter == this->allocated_mem.end()); // ptr was found in the list of allocated memory blocks
        this->allocated_mem.push_back(ptr);
    }

    void
    remove(void *ptr)
    {
        auto iter = find(ptr);
        assert(iter != this->allocated_mem.end()); // ptr was not found in the list of allocated memory blocks
        this->allocated_mem.erase(iter);
    }

    bool
    is_empty()
    {
        return this->allocated_mem.empty();
    }

    void
    clear()
    {
        this->allocated_mem.clear();
    }
};

class TestMetrics : public ::testing::Test
{
private:
protected:
    void
    SetUp() override
    {
        esp_log_wrapper_init();
        memset(&g_gw_mac_sta_str, 0, sizeof(g_gw_mac_sta_str));
        memset(&g_nrf52_firmware_version, 0, sizeof(g_nrf52_firmware_version));
        this->m_uptime = 0;
        g_pTestClass   = this;
        this->m_mem_alloc_trace.clear();
        this->m_malloc_cnt         = 0;
        this->m_malloc_fail_on_cnt = 0;
    }

    void
    TearDown() override
    {
        metrics_deinit();
        g_pTestClass = nullptr;
        esp_log_wrapper_deinit();
    }

public:
    int64_t       m_uptime;
    MemAllocTrace m_mem_alloc_trace;
    uint32_t      m_malloc_cnt {};
    uint32_t      m_malloc_fail_on_cnt {};

    TestMetrics();

    ~TestMetrics() override;
};

TestMetrics::TestMetrics()
    : Test()
    , m_uptime(0)
{
}

TestMetrics::~TestMetrics() = default;

extern "C" {

void *
os_malloc(const size_t size)
{
    if (++g_pTestClass->m_malloc_cnt == g_pTestClass->m_malloc_fail_on_cnt)
    {
        return nullptr;
    }
    void *ptr = malloc(size);
    assert(nullptr != ptr);
    g_pTestClass->m_mem_alloc_trace.add(ptr);
    return ptr;
}

void
os_free_internal(void *ptr)
{
    g_pTestClass->m_mem_alloc_trace.remove(ptr);
    free(ptr);
}

void *
os_calloc(const size_t nmemb, const size_t size)
{
    if (++g_pTestClass->m_malloc_cnt == g_pTestClass->m_malloc_fail_on_cnt)
    {
        return nullptr;
    }
    void *ptr = calloc(nmemb, size);
    assert(nullptr != ptr);
    g_pTestClass->m_mem_alloc_trace.add(ptr);
    return ptr;
}

const char *
os_task_get_name(void)
{
    static const char g_task_name[] = "main";
    return const_cast<char *>(g_task_name);
}

os_mutex_t
os_mutex_create_static(os_mutex_static_t *const p_mutex_static)
{
    return reinterpret_cast<os_mutex_t>(p_mutex_static);
}

void
os_mutex_delete(os_mutex_t *const ph_mutex)
{
    *ph_mutex = nullptr;
}

void
os_mutex_lock(os_mutex_t const h_mutex)
{
}

void
os_mutex_unlock(os_mutex_t const h_mutex)
{
}

int64_t
esp_timer_get_time()
{
    return g_pTestClass->m_uptime;
}

void
heap_caps_get_info(multi_heap_info_t *info, uint32_t caps)
{
    memset(info, 0, sizeof(*info));

    switch (caps)
    {
        case MALLOC_CAP_EXEC:
            info->total_free_bytes = 194796;
            break;
        case MALLOC_CAP_32BIT:
            info->total_free_bytes = 201116;
            break;
        case MALLOC_CAP_8BIT:
            info->total_free_bytes = 134284;
            break;
        case MALLOC_CAP_DMA:
            info->total_free_bytes = 134164;
            break;
        case MALLOC_CAP_PID2:
            info->total_free_bytes = 10;
            break;
        case MALLOC_CAP_PID3:
            info->total_free_bytes = 20;
            break;
        case MALLOC_CAP_PID4:
            info->total_free_bytes = 30;
            break;
        case MALLOC_CAP_PID5:
            info->total_free_bytes = 40;
            break;
        case MALLOC_CAP_PID6:
            info->total_free_bytes = 50;
            break;
        case MALLOC_CAP_PID7:
            info->total_free_bytes = 60;
            break;
        case MALLOC_CAP_SPIRAM:
            info->total_free_bytes = 70;
            break;
        case MALLOC_CAP_INTERNAL:
            info->total_free_bytes = 201116;
            break;
        case MALLOC_CAP_DEFAULT:
            info->total_free_bytes = 134284;
            break;
    }
}

size_t
heap_caps_get_largest_free_block(uint32_t caps)
{
    switch (caps)
    {
        case MALLOC_CAP_EXEC:
            return 65536;
        case MALLOC_CAP_32BIT:
            return 65537;
        case MALLOC_CAP_8BIT:
            return 65538;
        case MALLOC_CAP_DMA:
            return 65539;
        case MALLOC_CAP_PID2:
            return 65540;
        case MALLOC_CAP_PID3:
            return 65541;
        case MALLOC_CAP_PID4:
            return 65542;
        case MALLOC_CAP_PID5:
            return 65543;
        case MALLOC_CAP_PID6:
            return 65544;
        case MALLOC_CAP_PID7:
            return 65545;
        case MALLOC_CAP_SPIRAM:
            return 65546;
        case MALLOC_CAP_INTERNAL:
            return 65547;
        case MALLOC_CAP_DEFAULT:
            return 65548;
    }
    return 0;
}

fw_ver_str_t
fw_update_get_cur_version2(void)
{
    fw_ver_str_t version_str;
    snprintf(&version_str.buf[0], sizeof(version_str.buf), "v1.9.2-12-ga6893d9");
    return version_str;
}

} // extern "C"

#define TEST_CHECK_LOG_RECORD(level_, msg_) ESP_LOG_WRAPPER_TEST_CHECK_LOG_RECORD("metrics", level_, msg_)

/*** Unit-Tests
 * *******************************************************************************************************/

TEST_F(TestMetrics, test_metrics_init_deinit) // NOLINT
{
    metrics_init();
    metrics_received_advs_increment();
    metrics_deinit();
}

TEST_F(TestMetrics, test_metrics_received_advs_increment_without_init) // NOLINT
{
    metrics_received_advs_increment();
    metrics_deinit();
}

TEST_F(TestMetrics, test_metrics_generate) // NOLINT
{
    metrics_init();

    snprintf(&g_gw_mac_sta_str.str_buf[0], sizeof(g_gw_mac_sta_str), "AA:BB:CC:DD:EE:FF");
    snprintf(&g_nrf52_firmware_version.buf[0], sizeof(g_nrf52_firmware_version), "v0.7.2");

    this->m_uptime            = 15317668796;
    const char *p_metrics_str = metrics_generate();
    ASSERT_EQ(
        string("ruuvigw_received_advertisements 0\n"
               "ruuvigw_uptime_us 15317668796\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_EXEC\"} 194796\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_32BIT\"} 201116\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_8BIT\"} 134284\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_DMA\"} 134164\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID2\"} 10\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID3\"} 20\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID4\"} 30\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID5\"} 40\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID6\"} 50\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID7\"} 60\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_SPIRAM\"} 70\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_INTERNAL\"} 201116\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_DEFAULT\"} 134284\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_EXEC\"} 65536\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_32BIT\"} 65537\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_8BIT\"} 65538\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_DMA\"} 65539\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID2\"} 65540\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID3\"} 65541\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID4\"} 65542\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID5\"} 65543\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID6\"} 65544\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID7\"} 65545\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_SPIRAM\"} 65546\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_INTERNAL\"} 65547\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_DEFAULT\"} 65548\n"
               "ruuvigw_info{mac=\"AA:BB:CC:DD:EE:FF\",esp_fw=\"v1.9.2-12-ga6893d9\",nrf_fw=\"v0.7.2\"} 1\n"),
        string(p_metrics_str));
    os_free(p_metrics_str);

    metrics_received_advs_increment();
    this->m_uptime = 15317668797;

    p_metrics_str = metrics_generate();
    ASSERT_EQ(
        string("ruuvigw_received_advertisements 1\n"
               "ruuvigw_uptime_us 15317668797\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_EXEC\"} 194796\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_32BIT\"} 201116\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_8BIT\"} 134284\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_DMA\"} 134164\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID2\"} 10\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID3\"} 20\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID4\"} 30\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID5\"} 40\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID6\"} 50\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_PID7\"} 60\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_SPIRAM\"} 70\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_INTERNAL\"} 201116\n"
               "ruuvigw_heap_free_bytes{capability=\"MALLOC_CAP_DEFAULT\"} 134284\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_EXEC\"} 65536\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_32BIT\"} 65537\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_8BIT\"} 65538\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_DMA\"} 65539\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID2\"} 65540\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID3\"} 65541\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID4\"} 65542\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID5\"} 65543\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID6\"} 65544\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_PID7\"} 65545\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_SPIRAM\"} 65546\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_INTERNAL\"} 65547\n"
               "ruuvigw_heap_largest_free_block_bytes{capability=\"MALLOC_CAP_DEFAULT\"} 65548\n"
               "ruuvigw_info{mac=\"AA:BB:CC:DD:EE:FF\",esp_fw=\"v1.9.2-12-ga6893d9\",nrf_fw=\"v0.7.2\"} 1\n"),
        string(p_metrics_str));
    os_free(p_metrics_str);
    ASSERT_TRUE(esp_log_wrapper_is_empty());
    ASSERT_TRUE(g_pTestClass->m_mem_alloc_trace.is_empty());
}

TEST_F(TestMetrics, test_metrics_generate_malloc_failed) // NOLINT
{
    this->m_malloc_fail_on_cnt = 1;

    snprintf(&g_gw_mac_sta_str.str_buf[0], sizeof(g_gw_mac_sta_str), "AA:BB:CC:DD:EE:FF");
    snprintf(&g_nrf52_firmware_version.buf[0], sizeof(g_nrf52_firmware_version), "v0.7.2");

    this->m_uptime = 15317668796;
    ASSERT_EQ(nullptr, metrics_generate());

    TEST_CHECK_LOG_RECORD(ESP_LOG_ERROR, string("Can't allocate memory"));
    ASSERT_TRUE(esp_log_wrapper_is_empty());
    ASSERT_TRUE(g_pTestClass->m_mem_alloc_trace.is_empty());
}
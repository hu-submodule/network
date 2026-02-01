/**
 * @file      hs_network.h
 * @brief     网络模块头文件
 * @author    huenrong (sgyhy1028@outlook.com)
 * @date      2026-02-01 14:55:08
 *
 * @copyright Copyright (c) 2026 huenrong
 *
 */

#ifndef __HS_NETWORK_H
#define __HS_NETWORK_H

#include <stdint.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C"
{
#endif

// MAC 地址字符串长度(例如: xx:xx:xx:xx:xx:xx)
#define HS_NETWORK_MAC_ADDRSTRLEN 18

// IPv4 信息
typedef struct hs_ipv4_info
{
    char ip[INET_ADDRSTRLEN]; // IPv4 地址
    uint8_t prefix;           // 子网掩码前缀
} hs_ipv4_info_t;

// IPv6 信息
typedef struct hs_ipv6_info
{
    char ip[INET6_ADDRSTRLEN]; // IPv6 地址
    uint8_t prefix;            // 子网掩码前缀
} hs_ipv6_info_t;

/**
 * @brief 获取指定接口的 MAC 地址
 *
 * @param[in]  ifname : 网络接口名
 * @param[out] mac    : MAC 地址
 * @param[in]  mac_len: MAC 地址缓冲区长度（可使用 HS_NETWORK_MAC_ADDRSTRLEN 宏）
 *
 * @return 0 : 成功
 * @return <0: 失败
 */
int hs_network_get_mac_addr(const char *ifname, char *mac, const size_t mac_len);

/**
 * @brief 获取指定接口的 IPv4 信息
 *
 * @param[in]  ifname         : 网络接口名
 * @param[out] ipv4_info      : IPv4 信息
 * @param[in]  ipv4_info_count: IPv4 信息缓冲区长度
 *
 * @return >0: 实际获取到的 IPv4 信息数量
 * @return 0 : 未获取到 IPv4 信息
 * @return <0: 失败
 */
int hs_network_get_ipv4_info(const char *ifname, hs_ipv4_info_t *ipv4_info, const size_t ipv4_info_count);

/**
 * @brief 获取指定接口的 IPv4 默认网关
 *
 * @param[in]  ifname     : 网络接口名
 * @param[out] gateway    : IPv4 默认网关
 * @param[in]  gateway_len: IPv4 默认网关缓冲区长度
 *
 * @return >0: 成功
 * @return 0 : 没有找到默认网关
 * @return <0: 失败
 */
int hs_network_get_ipv4_default_gateway(const char *ifname, char *gateway, const size_t gateway_len);

/**
 * @brief 获取指定接口的 IPv6 信息
 *
 * @note 内部会跳过 link-local (fe80::/10) 地址
 *
 * @param[in]  ifname         : 网络接口名
 * @param[out] ipv6_info      : IPv6 信息
 * @param[in]  ipv6_info_count: IPv6 信息缓冲区长度
 *
 * @return >0: 实际获取到的 IPv6 信息数量
 * @return 0 : 未获取到 IPv6 信息
 * @return <0: 失败
 */
int hs_network_get_ipv6_info(const char *ifname, hs_ipv6_info_t *ipv6_info, const size_t ipv6_info_count);

/**
 * @brief 获取指定接口的 IPv6 默认网关
 *
 * @param[in]  ifname     : 网络接口名
 * @param[out] gateway    : IPv6 默认网关
 * @param[in]  gateway_len: IPv6 默认网关缓冲区长度
 *
 * @return >0: 成功
 * @return 0 : 没有找到默认网关
 * @return <0: 失败
 */
int hs_network_get_ipv6_default_gateway(const char *ifname, char *gateway, const size_t gateway_len);

/**
 * @brief 将点分十进制格式子网掩码转换为 CIDR 格式前缀
 *
 * @param[in]  netmask: 点分十进制格式子网掩码
 * @param[out] prefix : CIDR 格式前缀
 *
 * @return 0 : 成功
 * @return <0: 失败
 */
int hs_network_ipv4_netmask_to_prefix(const char *netmask, uint8_t *prefix);

/**
 * @brief 将 CIDR 格式前缀子网掩码转换为点分十进制格式
 *
 * @param[in]  prefix     : CIDR 格式前缀
 * @param[out] netmask    : 点分十进制格式子网掩码
 * @param[in]  netmask_len: 点分十进制格式子网掩码缓冲区长度
 *
 * @return 0 : 成功
 * @return <0: 失败
 */
int hs_network_ipv4_prefix_to_netmask(const uint8_t prefix, char *netmask, const size_t netmask_len);

/**
 * @brief ping 主机
 *
 * @note 该函数使用 ICMP 协议进行 ping 操作，需要 root 权限
 *
 * @param[in] hostname    : 主机地址(支持域名和 IPv4 地址)
 * @param[in] ping_count  : ping 次数
 * @param[in] timeout_msec: 超时时间(单位: 毫秒)
 *
 * @return 0 : 成功
 * @return <0: 失败
 */
int hs_network_ping_host(const char *hostname, const uint8_t ping_count, const uint16_t timeout_msec);

#ifdef __cplusplus
}
#endif

#endif // __HS_NETWORK_H

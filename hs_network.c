/**
 * @file      hs_network.c
 * @brief     网络模块头文件
 * @author    huenrong (sgyhy1028@outlook.com)
 * @date      2026-02-01 14:55:01
 *
 * @copyright Copyright (c) 2026 huenrong
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#include "hs_network.h"

/**
 * @brief netlink 获取默认网关
 *
 * @param[in]  ifname     : 网络接口名
 * @param[in]  family     : 协议族(AF_INET 或 AF_INET6)
 * @param[out] gateway    : 默认网关
 * @param[in]  gateway_len: 默认网关缓冲区长度
 *
 * @return >0: 成功
 * @return 0 : 没有找到默认网关
 * @return <0: 失败
 */
static int hs_network_netlink_get_default_gateway(const char *ifname, const int family, char *gateway,
                                                  const size_t gateway_len)
{
    if (ifname == NULL)
    {
        return -1;
    }

    if (gateway == NULL)
    {
        return -2;
    }

    if ((family == AF_INET) && (gateway_len < INET_ADDRSTRLEN))
    {
        return -3;
    }
    else if ((family == AF_INET6) && (gateway_len < INET6_ADDRSTRLEN))
    {
        return -3;
    }

    uint32_t ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        return -4;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
    {
        return -5;
    }

    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    rtm->rtm_family = family;
    rtm->rtm_table = RT_TABLE_MAIN;

    struct sockaddr_nl sa = {0};
    sa.nl_family = AF_NETLINK;

    if (sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        close(fd);

        return -6;
    }

    ssize_t len = 0;
    while ((len = recv(fd, buf, sizeof(buf), 0)) > 0)
    {
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
        {
            // NLMSG_DONE：数据包结束，还没找到默认网关
            if (h->nlmsg_type == NLMSG_DONE)
            {
                close(fd);

                return 0;
            }

            if (h->nlmsg_type != RTM_NEWROUTE)
            {
                continue;
            }

            struct rtmsg *route = (struct rtmsg *)NLMSG_DATA(h);

            // 只关心默认路由
            // rtm_dst_len == 0 表示默认路由，若想获取非默认路由，则取消此判断
            // 默认路由的前缀长度为 0 (0.0.0.0/0 或 ::/0)
            if ((route->rtm_family != family) || (route->rtm_dst_len != 0))
            {
                continue;
            }

            struct rtattr *attr = RTM_RTA(route);
            int attr_len = RTM_PAYLOAD(h);
            uint32_t oif = 0;
            uint8_t gw_addr[16] = {0};

            for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len))
            {
                if (attr->rta_type == RTA_OIF)
                {
                    oif = *(uint32_t *)RTA_DATA(attr);
                }
                else if (attr->rta_type == RTA_GATEWAY)
                {
                    // IPv4 网关长度为 4 字节，IPv6 网关长度为 16 字节
                    memcpy(gw_addr, RTA_DATA(attr), (family == AF_INET ? 4 : 16));
                }
            }

            if (oif == ifindex)
            {
                if ((family == AF_INET) && (*(uint32_t *)gw_addr != 0))
                {
                    inet_ntop(AF_INET, gw_addr, gateway, gateway_len);
                    close(fd);

                    return 1;
                }
                else if ((family == AF_INET6) && (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)gw_addr)))
                {
                    inet_ntop(AF_INET6, gw_addr, gateway, gateway_len);
                    close(fd);

                    return 1;
                }
            }
        }
    }

    close(fd);

    return -7;
}

/**
  * @brief 计算 ICMP 校验和
  *
  * @param[in] src_data    : 待校验源数据
  * @param[in] src_data_len: 待校验源数据长度
  *
  * @return 校验值
  */
static uint16_t hs_network_icmp_check_sum(const uint16_t *src_data, const size_t src_data_len)
{
    if (src_data == NULL)
    {
        return 0;
    }

    if (src_data_len == 0)
    {
        return 0;
    }

    size_t src_data_len_tmp = src_data_len;
    uint32_t sum = 0;

    while (src_data_len_tmp > 1)
    {
        sum += *src_data++;
        src_data_len_tmp -= 2;
    }

    if (src_data_len_tmp == 1)
    {
        sum += *(uint8_t *)src_data;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

/**
 * @brief ping 指定地址
 *
 * @param[in] fd          : 文件描述符
 * @param[in] ping_addr   : 待 ping 的地址
 * @param[in] seq_num     : ping 的序列号
 * @param[in] timeout_msec: 超时时间(单位: 毫秒)
 *
 * @return 0 : 成功
 * @return <0: 失败
 */
static int hs_network_ping(const int fd, const struct sockaddr *ping_addr, const uint16_t seq_num,
                           const uint16_t timeout_msec)
{
#define ICMP_DEFAULT_DATA_LEN 56
#define ICMP_CUSTOM_DATA_LEN  9

    if (fd < 0)
    {
        return -1;
    }

    if (ping_addr == NULL)
    {
        return -2;
    }

    if (timeout_msec == 0)
    {
        return -3;
    }

    // 8字节头部 + 56字节默认数据 + 自定义数据
    char send_icmp_packet[ICMP_MINLEN + ICMP_DEFAULT_DATA_LEN + ICMP_CUSTOM_DATA_LEN] = {0};
    struct icmp *send_icmp = (struct icmp *)send_icmp_packet;

    // ICMP头部
    memset(send_icmp_packet, 0, sizeof(send_icmp_packet));
    send_icmp->icmp_type = ICMP_ECHO;
    send_icmp->icmp_code = 0;
    send_icmp->icmp_id = (uint16_t)getpid();
    send_icmp->icmp_seq = seq_num;

    // 自定义数据
    memcpy(send_icmp->icmp_data, "sgyhy1028", ICMP_CUSTOM_DATA_LEN);

    // 校验和
    send_icmp->icmp_cksum = hs_network_icmp_check_sum((uint16_t *)send_icmp_packet, sizeof(send_icmp_packet));

    // 发送请求
    int ret = sendto(fd, send_icmp_packet, sizeof(send_icmp_packet), 0, ping_addr, sizeof(struct sockaddr_in));
    if (ret <= 0)
    {
        return -4;
    }

    fd_set recv_fds;
    FD_ZERO(&recv_fds);
    FD_SET(fd, &recv_fds);

    struct timeval timeout;
    timeout.tv_sec = timeout_msec / 1000;
    timeout.tv_usec = (timeout_msec % 1000) * 1000;

    ret = select(fd + 1, &recv_fds, NULL, NULL, &timeout);
    if (ret <= 0)
    {
        return -5;
    }

    if (!FD_ISSET(fd, &recv_fds))
    {
        return -6;
    }

    char recv_data[1024] = {0};
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ret = recvfrom(fd, recv_data, sizeof(recv_data), 0, (struct sockaddr *)&from, &from_len);
    if (ret < 0)
    {
        return -7;
    }

    // 基本长度检查
    if (ret < (ssize_t)sizeof(struct ip))
    {
        return -8;
    }

    // 解析 IP 头
    struct ip *ip_header = (struct ip *)recv_data;
    if (ip_header->ip_v != 4)
    {
        return -9;
    }

    uint32_t ip_header_len = ip_header->ip_hl << 2;
    if (ret < (ssize_t)(ip_header_len + ICMP_MINLEN))
    {
        return -10;
    }

    // 解析 ICMP
    struct icmp *recv_icmp = (struct icmp *)(recv_data + ip_header_len);

    // 校验 ICMP 响应
    if ((recv_icmp->icmp_type != ICMP_ECHOREPLY) || (recv_icmp->icmp_id != send_icmp->icmp_id) ||
        (recv_icmp->icmp_seq != send_icmp->icmp_seq) ||
        (memcmp(recv_icmp->icmp_data, send_icmp->icmp_data, ICMP_CUSTOM_DATA_LEN) != 0))
    {
        return -11;
    }

    return 0;
}

int hs_network_get_mac_addr(const char *ifname, char *mac, const size_t mac_len)
{
    if (ifname == NULL)
    {
        return -1;
    }

    if (mac == NULL)
    {
        return -2;
    }

    if (mac_len < HS_NETWORK_MAC_ADDRSTRLEN)
    {
        return -3;
    }

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0)
    {
        return -4;
    }

    bool found = false;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if ((ifa->ifa_name == NULL) || (strcmp(ifa->ifa_name, ifname) != 0) || (ifa->ifa_addr == NULL))
        {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_PACKET)
        {
            struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;

            if (s->sll_halen == 6)
            {
                snprintf(mac, mac_len, "%02x:%02x:%02x:%02x:%02x:%02x", s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                         s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
                found = true;

                break;
            }
        }
    }

    freeifaddrs(ifaddr);

    if (!found)
    {
        return -4;
    }

    return 0;
}

int hs_network_get_ipv4_info(const char *ifname, hs_ipv4_info_t *ipv4_info, const size_t ipv4_info_count)
{
    if (ifname == NULL)
    {
        return -1;
    }

    if (ipv4_info == NULL)
    {
        return -2;
    }

    if (ipv4_info_count == 0)
    {
        return -3;
    }

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0)
    {
        return -4;
    }

    int count = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if ((ifa->ifa_name == NULL) || (strcmp(ifa->ifa_name, ifname) != 0) || (ifa->ifa_addr == NULL) ||
            (ifa->ifa_addr->sa_family != AF_INET) || (ifa->ifa_netmask == NULL))
        {
            continue;
        }

        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ipv4_info[count].ip, INET_ADDRSTRLEN);

        sin = (struct sockaddr_in *)ifa->ifa_netmask;
        uint32_t mask = ntohl(sin->sin_addr.s_addr);
        // __builtin_popcount：GCC 内建函数，计算 1 的个数
        ipv4_info[count].prefix = __builtin_popcount(mask);

        count++;
        if (count >= (int)ipv4_info_count)
        {
            break;
        }
    }

    freeifaddrs(ifaddr);

    return count;
}

int hs_network_get_ipv4_default_gateway(const char *ifname, char *gateway, const size_t gateway_len)
{
    return hs_network_netlink_get_default_gateway(ifname, AF_INET, gateway, gateway_len);
}

int hs_network_get_ipv6_info(const char *ifname, hs_ipv6_info_t *ipv6_info, const size_t ipv6_info_count)
{
    if (ifname == NULL)
    {
        return -1;
    }

    if (ipv6_info == NULL)
    {
        return -2;
    }

    if (ipv6_info_count == 0)
    {
        return -3;
    }

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0)
    {
        return -4;
    }

    int count = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if ((ifa->ifa_name == NULL) || (strcmp(ifa->ifa_name, ifname) != 0) || (ifa->ifa_addr == NULL) ||
            (ifa->ifa_addr->sa_family != AF_INET6) || (ifa->ifa_netmask == NULL))
        {
            continue;
        }

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
        // 跳过 link-local (fe80::/10) 地址
        if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
        {
            continue;
        }
        inet_ntop(AF_INET6, &sin6->sin6_addr, ipv6_info[count].ip, INET6_ADDRSTRLEN);

        struct sockaddr_in6 *netmask = (struct sockaddr_in6 *)ifa->ifa_netmask;
        uint8_t mask_count = 0;
        for (uint8_t i = 0; i < 16; i++)
        {
            // __builtin_popcount：GCC 内建函数，计算 1 的个数
            mask_count += __builtin_popcount(netmask->sin6_addr.s6_addr[i]);
        }
        ipv6_info[count].prefix = mask_count;

        count++;
        if (count >= (int)ipv6_info_count)
        {
            break;
        }
    }

    freeifaddrs(ifaddr);

    return count;
}

int hs_network_get_ipv6_default_gateway(const char *ifname, char *gateway, const size_t gateway_len)
{
    return hs_network_netlink_get_default_gateway(ifname, AF_INET6, gateway, gateway_len);
}

int hs_network_ipv4_netmask_to_prefix(const char *netmask, uint8_t *prefix)
{
    if (netmask == NULL)
    {
        return -1;
    }

    if (strlen(netmask) > INET_ADDRSTRLEN)
    {
        return -2;
    }

    if (prefix == NULL)
    {
        return -3;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, netmask, &addr) != 1)
    {
        return -4;
    }

    uint32_t netmask_num = ntohl(addr.s_addr);
    bool found_zero = false; // 已经遇到过 0
    uint8_t count = 0;       // 1 的个数
    for (int i = 31; i >= 0; i--)
    {
        if (netmask_num & (1 << i))
        {
            // 1 出现在 0 之后，无效子网掩码
            if (found_zero)
            {
                return -5;
            }

            count++;
        }
        else
        {
            found_zero = true;
        }
    }

    *prefix = count;

    return 0;
}

int hs_network_ipv4_prefix_to_netmask(const uint8_t prefix, char *netmask, const size_t netmask_len)
{
    if (prefix > 32)
    {
        return -1;
    }

    if (netmask == NULL)
    {
        return -2;
    }

    if (netmask_len < INET_ADDRSTRLEN)
    {
        return -3;
    }

    uint32_t netmask_num = 0xFFFFFFFF << (32 - prefix);
    struct in_addr addr;
    addr.s_addr = htonl(netmask_num);
    if (inet_ntop(AF_INET, &addr, netmask, INET_ADDRSTRLEN) == NULL)
    {
        return -4;
    }

    return 0;
}

int hs_network_ping_host(const char *hostname, const uint8_t ping_count, const uint16_t timeout_msec)
{
    if (hostname == NULL)
    {
        return -1;
    }

    if (ping_count == 0)
    {
        return -2;
    }

    if (timeout_msec == 0)
    {
        return -3;
    }

    struct addrinfo hints = {0};
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    struct addrinfo *result;
    int ret = getaddrinfo(hostname, NULL, &hints, &result);
    if (ret != 0)
    {
        return -4;
    }

    struct sockaddr_in ping_addr;
    memcpy(&ping_addr, result->ai_addr, sizeof(ping_addr));
    freeaddrinfo(result);

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
    {
        return -5;
    }

    for (uint8_t i = 1; i <= ping_count; i++)
    {
        if (hs_network_ping(fd, (struct sockaddr *)&ping_addr, i, timeout_msec) != 0)
        {
            close(fd);

            return -6;
        }
    }

    close(fd);

    return 0;
}

#ifndef IPINTEL_H
#define IPINTEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ipintel_db ipintel_db;

#define IPINTEL_ALLOW     0
#define IPINTEL_CHALLENGE 1
#define IPINTEL_BLOCK     2

ipintel_db* ipintel_open(const char* path);
void        ipintel_close(ipintel_db* db);

uint64_t ipintel_v4_count(const ipintel_db* db);
uint64_t ipintel_v6_count(const ipintel_db* db);

uint32_t ipintel_lookup_v4_flags(const ipintel_db* db, uint32_t ip_host_order);
uint8_t  ipintel_lookup_v4_score(const ipintel_db* db, uint32_t ip_host_order);
uint8_t  ipintel_lookup_v4_action(const ipintel_db* db,
                                  uint32_t ip_host_order,
                                  uint8_t block_threshold,
                                  uint8_t challenge_threshold);

uint32_t ipintel_lookup_v6_flags(const ipintel_db* db, const uint8_t ip[16]);
uint8_t  ipintel_lookup_v6_score(const ipintel_db* db, const uint8_t ip[16]);
uint8_t  ipintel_lookup_v6_action(const ipintel_db* db,
                                  const uint8_t ip[16],
                                  uint8_t block_threshold,
                                  uint8_t challenge_threshold);

#ifdef __cplusplus
}
#endif

#endif

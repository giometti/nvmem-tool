#ifndef NVMEM_TOOL_H
#define NVMEM_TOOL_H

/*
 * nvmem-tool.h - MVMEM header file
 *
 * (c) 2025 Rodolfo Giometti <giometti@enneenne.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>
#include <linux/limits.h>

enum nvmem_type_e {
        NVMEM_TYPE_UNKNOWN,
        NVMEM_TYPE_EEPROM,
        NVMEM_TYPE_OTP,
        NVMEM_TYPE_BATTERY_BACKED,
        NVMEM_TYPE_FRAM,
        __NVMEM_TYPE_END
};

#define NVMEM_STR_MAXLEN        64

struct nvmem_ofnode_t {
        char name[NVMEM_STR_MAXLEN];
                        /* bus/nvmem/devices/<dev>/of_node/<node>             */
        uint32_t off;   /* bus/nvmem/devices/<dev>/of_node/<node>/reg         */
        uint32_t len;

        char sym[NVMEM_STR_MAXLEN];
                        /* firmware/devicetree/base/<sym>/name                */
        char cell[NVMEM_STR_MAXLEN];
                        /* firmware/devicetree/base/<sym>/nvmem-cell-names ->
                         * bus/nvmem/devices/<dev>/of_node/phandle            */
};

struct nvmem_dev_t {
        char name[NVMEM_STR_MAXLEN];    /* bus/nvmem/devices/<dev>            */
        enum nvmem_type_e type;         /* bus/nvmem/devices/<dev>/type       */

        char ofname[NVMEM_STR_MAXLEN];
                        /* basename(bus/nvmem/devices/<dev>/of_node)          */
        struct nvmem_ofnode_t *ofnode;
        size_t ofnode_num;      /* bus/nvmem/devices/<dev>/of_node/<node>     */
};

int sysfs_raw_read_u32(const char *path, uint32_t val[], size_t num);
uint32_t sysfs_read_phandle(const char *path);
struct nvmem_ofnode_t *add_new_nvmem_cell(struct nvmem_dev_t *dev);
void parse_symbols_for_nvmem(uint32_t phandle, char *sym, char *cell);

/*
 * Available parsers
 */
int parse_fixed_layout(struct nvmem_dev_t *dev, const char *sysfs);

#endif /* NVMEM_TOOL_H */

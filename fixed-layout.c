/*
 * fixed-layout.c - NVMEM fixed-layout (and legacy-layout) parser
 *
 * (c) 2024-2025 Rodolfo Giometti <giometti@enneenne.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include "misc.h"
#include "nvmem-tool.h"

static int sysfs_read_reg(const char *path, uint32_t *off, uint32_t *len)
{
        uint32_t v[2];
        int ret;

        ret = sysfs_raw_read_u32(path, v, 2);
        if (ret < 0) {
                dbg("cannot read file %s", path);
                return ret;
        }

        *off = be32toh(v[0]);
        *len = be32toh(v[1]);

        return 0;
}

static int nvmem_get_reg(const char *sysfs, const char *node,
                                uint32_t *off, uint32_t *len)
{
        char *path;
        int ret;

        ret = asprintf(&path, "%s/%s/reg", sysfs, node);
        if (ret < 0)
                fatal("cannot allocate memory");

        ret = sysfs_read_reg(path, off, len);
        free(path);

        return ret;
}

static uint32_t nvmem_get_phandle(const char *sysfs, const char *node)
{
        char *path;
        uint32_t cells;
        int ret;

        ret = asprintf(&path, "%s/%s/phandle", sysfs, node);
        if (ret < 0)
                fatal("cannot allocate memory");

        cells = sysfs_read_phandle(path);

        free(path);

        return cells;
}

/*
 * Main parsing function
 */

int parse_fixed_layout(struct nvmem_dev_t *dev, const char *sysfs)
{
        DIR *d;
        struct dirent *e;
        struct nvmem_ofnode_t *node;
        uint32_t phandle;
        int ret;

        dbg("sysfs=%s", sysfs);
        d = opendir(sysfs);
        if (!d)
                return -ENOENT;

        while ((e = readdir(d))) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                        continue;
                if (e->d_type != DT_DIR)
                        continue;
                dbg("name=%s", e->d_name);
                BUG_ON(strlen(e->d_name) >= NVMEM_STR_MAXLEN);

                node = add_new_nvmem_cell(dev);
                strncpy(node->name, e->d_name, NVMEM_STR_MAXLEN);
                ret = nvmem_get_reg(sysfs, node->name, &node->off, &node->len);
                if (ret < 0) {
                        node->off = node->len = 0;
                        dbg("%s: setting node offset and length to zero",
                                        node->name);
                }

                phandle = nvmem_get_phandle(sysfs, node->name);
                parse_symbols_for_nvmem(phandle, node->sym, node->cell);

                dbg("name=%s off=0x%x len=0x%x phandle=0x%x sym=%s cell=%s",
                        node->name, node->off, node->len,
                        phandle, node->sym, node->cell);

        }

        closedir(d);

        return 0;
}

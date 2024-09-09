#include "SysInfo.h"
#include "MemoryHandle.h"
#include "ComProtocol.h"
#include "Logger.h"
#include <sys/statfs.h>

namespace chw {

/*
 * Structure for memory and swap space utilization statistics.
 *
 * Used by: sadc, sar, sadf, pidstat
 */
struct stats_memory {
	unsigned long long frmkb;
	unsigned long long bufkb;
	unsigned long long camkb;
	unsigned long long tlmkb;
	unsigned long long frskb;
	unsigned long long tlskb;
	unsigned long long caskb;
	unsigned long long comkb;
	unsigned long long activekb;
	unsigned long long inactkb;
	unsigned long long dirtykb;
	unsigned long long anonpgkb;
	unsigned long long slabkb;
	unsigned long long kstackkb;
	unsigned long long pgtblkb;
	unsigned long long vmusedkb;
	unsigned long long availablekb;
    unsigned long long SReclaimable;
};

#define PRE	""
#define MEMINFO			PRE "/proc/meminfo"

/*
 ***************************************************************************
 * 读取挂载设备列表： /proc/mounts
 * 第1列：Device mount的设备
 * 第2列：Mount Point 挂载点，也就是挂载的路径
 * 第3列：File System Type 文件系统类型，如ext4、xfs等
 * 第4列：Options 挂载选项，包括读写权限等参数
 * 第5列：无用内容，保持内容和/etc/fstab格式一致
 * 第6列：无用内容，保持内容和/etc/fstab格式一致
 *
 * tmpfs: 是 Linux 内核中的一个虚拟文件系统，它将数据存储在内存中而不是硬盘上,可以快速访问数据.
 * udev: /dev目录下管理的设备，/dev目录是一个特殊的文件系统，它包含了对于系统中设备文件的引用，不占用磁盘空间
 ***************************************************************************
 */
uint32_t CptDisk(uint64_t& total, uint64_t& avaiable)
{
    FILE *f;
    char mount_dev[256];
    char mount_dir[256];
    char mount_type[256];
    char mount_opts[256];
    int mount_freq;
    int mount_passno;
    int match;

    f = fopen("/proc/mounts", "r");
    if (!f) {
        PrintD("could not open /proc/mounts,errno=%d(%s).",errno,strerror(errno));
        return chw::fail;
    }

    do {
        match = fscanf(f, "%255s %255s %255s %255s %d %d\n",
                       mount_dev, mount_dir, mount_type,
                       mount_opts, &mount_freq, &mount_passno);
  
        if(strcmp(mount_type,"tmpfs") != 0 && strcmp(mount_type,"udev") != 0)
        {
            struct statfs diskInfo;  
            statfs(mount_dir, &diskInfo);  
            unsigned long long blocksize = diskInfo.f_bsize;    //每个block里包含的字节数  
            unsigned long long totalsize = blocksize * diskInfo.f_blocks;   //总的字节数，f_blocks为block的数目  
      
            // unsigned long long freeDisk = diskInfo.f_bfree * blocksize; //剩余空间的大小  
            unsigned long long availableDisk = diskInfo.f_bavail * blocksize;   //可用空间大小  
    
            total += totalsize;
            avaiable += availableDisk;
        }

        _SET_MEM_(mount_dir,256,0,256);
        _SET_MEM_(mount_type,256,0,256);
    } while (match != EOF);

    total /= 1024;
    avaiable /= 1024;

    fclose(f);
    return chw::success;
}


/*
 ***************************************************************************
 * Read memory statistics from /proc/meminfo.
 *
 * IN:
 * @st_memory	Structure where stats will be saved.
 *
 * OUT:
 * @st_memory	Structure with statistics.
 *
 * RETURNS:
 * 1 on success, 0 otherwise.
 *
 * USED BY:
 * sadc, pidstat
 ***************************************************************************
 */
int read_meminfo(struct stats_memory *st_memory)
{
	FILE *fp;
	char line[128];

	if ((fp = fopen(MEMINFO, "r")) == NULL)
		return 0;

	while (fgets(line, sizeof(line), fp) != NULL) {

		if (!strncmp(line, "MemTotal:", 9)) {
			/* Read the total amount of memory in kB */
			sscanf(line + 9, "%llu", &st_memory->tlmkb);
		}
		else if (!strncmp(line, "MemFree:", 8)) {
			/* Read the amount of free memory in kB */
			sscanf(line + 8, "%llu", &st_memory->frmkb);
		}
		else if (!strncmp(line, "MemAvailable:", 13)) {
			/* Read the amount of available memory in kB */
			sscanf(line + 13, "%llu", &st_memory->availablekb);
		}
		else if (!strncmp(line, "Buffers:", 8)) {
			/* Read the amount of buffered memory in kB */
			sscanf(line + 8, "%llu", &st_memory->bufkb);
		}
		else if (!strncmp(line, "Cached:", 7)) {
			/* Read the amount of cached memory in kB */
			sscanf(line + 7, "%llu", &st_memory->camkb);
		}
		else if (!strncmp(line, "SwapCached:", 11)) {
			/* Read the amount of cached swap in kB */
			sscanf(line + 11, "%llu", &st_memory->caskb);
		}
		else if (!strncmp(line, "Active:", 7)) {
			/* Read the amount of active memory in kB */
			sscanf(line + 7, "%llu", &st_memory->activekb);
		}
		else if (!strncmp(line, "Inactive:", 9)) {
			/* Read the amount of inactive memory in kB */
			sscanf(line + 9, "%llu", &st_memory->inactkb);
		}
		else if (!strncmp(line, "SwapTotal:", 10)) {
			/* Read the total amount of swap memory in kB */
			sscanf(line + 10, "%llu", &st_memory->tlskb);
		}
		else if (!strncmp(line, "SwapFree:", 9)) {
			/* Read the amount of free swap memory in kB */
			sscanf(line + 9, "%llu", &st_memory->frskb);
		}
		else if (!strncmp(line, "Dirty:", 6)) {
			/* Read the amount of dirty memory in kB */
			sscanf(line + 6, "%llu", &st_memory->dirtykb);
		}
		else if (!strncmp(line, "Committed_AS:", 13)) {
			/* Read the amount of commited memory in kB */
			sscanf(line + 13, "%llu", &st_memory->comkb);
		}
		else if (!strncmp(line, "AnonPages:", 10)) {
			/* Read the amount of pages mapped into userspace page tables in kB */
			sscanf(line + 10, "%llu", &st_memory->anonpgkb);
		}
		else if (!strncmp(line, "Slab:", 5)) {
			/* Read the amount of in-kernel data structures cache in kB */
			sscanf(line + 5, "%llu", &st_memory->slabkb);
		}
		else if (!strncmp(line, "KernelStack:", 12)) {
			/* Read the kernel stack utilization in kB */
			sscanf(line + 12, "%llu", &st_memory->kstackkb);
		}
		else if (!strncmp(line, "PageTables:", 11)) {
			/* Read the amount of memory dedicated to the lowest level of page tables in kB */
			sscanf(line + 11, "%llu", &st_memory->pgtblkb);
		}
		else if (!strncmp(line, "VmallocUsed:", 12)) {
			/* Read the amount of vmalloc area which is used in kB */
			sscanf(line + 12, "%llu", &st_memory->vmusedkb);
		}
        else if (!strncmp(line, "SReclaimable:", 13)) {
			sscanf(line + 13, "%llu", &st_memory->SReclaimable);
		}
	}

	fclose(fp);
	return 1;
}

uint32_t CptMemory(uint64_t& MemTotal, uint64_t& MemAvailable)
{
    stats_memory st_memory;
    if(read_meminfo(&st_memory) == 1)
    {
        MemTotal = st_memory.tlmkb;
        MemAvailable = st_memory.frmkb + st_memory.bufkb + st_memory.camkb + st_memory.SReclaimable;
        return chw::success;
    }
    
    return chw::fail;
}

}// namespace chw
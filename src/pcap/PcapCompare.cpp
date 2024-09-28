#include "PcapCompare.h"

#include <thread>
#include "PcapParse.h"
#include "Semaphore.h"
#include "GlobalValue.h"
#include "PcapParse.h"
#include "Logger.h"
#include "MemoryHandle.h"

/*
# 默认文本格式打开
vim -b ens33.pcap
# 切换到16进制编辑，-c 32选项表示每行显示32个字节
:%!xxd
# 编辑完成后切换回文本格式
:%!xxd -r
# 保存
:wq

6754
84 00 00 00 00 01 00 00  00 04 06 5f 64 6f 73 76
85 00 00 00 00 01 00 00  00 04 06 5f 64 6f 73 76
*/
INSTANCE_IMP(PcapCompare)

static chw::Semaphore sem;
void ParseThread(PcapParse* cap,char* file)
{
	cap->parse_file(file);

	sem.post();
}


void PcapCompare::CompareFile()
{
	PcapParse cap1;
	PcapParse cap2;

	std::thread t1(ParseThread,&cap1,gConfigCmd.file1);
	std::thread t2(ParseThread,&cap2,gConfigCmd.file2);
	t1.detach();
	t2.detach();

    sem.wait();
    sem.wait();

	//todo:数据量大可以多开几个线程分段比较
	//找到第一个不同的字节停止
	int64_t iDiffIndex = -1;
	uint32_t uMinlen = cap1._cmpbuf.size < cap2._cmpbuf.size ? cap1._cmpbuf.size : cap2._cmpbuf.size;
	for(uint32_t index=0;index<uMinlen;index++)
	{
		if(cap1._cmpbuf.buf[index] != cap2._cmpbuf.buf[index])
		{
			iDiffIndex = index;
			break;
		}
	}

	if(iDiffIndex < 0 )
	{
		PrintD("According to the matching conditions and start end position, two file is same.");
		exit(0);
	}

	cap1._cmpbuf.first = false;
	cap1._cmpbuf.size = 0;
	cap1._cmpbuf.uDiff = iDiffIndex;
	cap2._cmpbuf.first = false;
	cap2._cmpbuf.size = 0;
	cap2._cmpbuf.uDiff = iDiffIndex;

	std::thread t3(ParseThread,&cap1,gConfigCmd.file1);
	std::thread t4(ParseThread,&cap2,gConfigCmd.file2);
	t3.detach();
	t4.detach();

    sem.wait();
    sem.wait();
}

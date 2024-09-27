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
void ParseThread(chw::ComMatchBuf* mbuf,char* file)
{
	PcapParse pp;
	pp.parse_file(file,*mbuf);

	sem.post();
}


void PcapCompare::CompareFile()
{
	std::thread t1(ParseThread,&_buffer1,gConfigCmd.file1);
	std::thread t2(ParseThread,&_buffer2,gConfigCmd.file2);
	t1.detach();
	t2.detach();

    sem.wait();
    sem.wait();

	//todo:数据量大可以多开几个线程分段比较
	int64_t iDiffIndex = -1;
	uint32_t uMinlen = _buffer1.size < _buffer2.size ? _buffer1.size : _buffer2.size;
	for(uint32_t index=0;index<uMinlen;index++)
	{
		if(_buffer1.buf[index] != _buffer2.buf[index])
		{
			iDiffIndex = index;
			break;
		}
	}

	_RAM_DEL_(_buffer1.buf);
	_RAM_DEL_(_buffer2.buf);

	if(iDiffIndex < 0 )
	{
		PrintD("According to the matching conditions and start end position, two file is same.");
		exit(0);
	}

	_buffer1.first = false;
	_buffer1.size = 0;
	_buffer1.uDiff = iDiffIndex;
	_buffer2.first = false;
	_buffer2.size = 0;
	_buffer2.uDiff = iDiffIndex;

	std::thread t3(ParseThread,&_buffer1,gConfigCmd.file1);
	std::thread t4(ParseThread,&_buffer2,gConfigCmd.file2);
	t3.detach();
	t4.detach();

    sem.wait();
    sem.wait();

	_RAM_DEL_(_buffer1.buf);
	_RAM_DEL_(_buffer2.buf);
}

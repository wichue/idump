#include "PcapCompare.h"

#include <thread>
#include "PcapParse.h"
#include "Semaphore.h"
#include "GlobalValue.h"
#include "PcapParse.h"
#include "Logger.h"

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

	uint32_t uDiffIndex = 0;
	uint32_t uMinlen = _buffer1.size < _buffer2.size ? _buffer1.size : _buffer2.size;
	for(uint32_t index=0;index<uMinlen;index++)
	{
		if(_buffer1.buf[index] != _buffer2.buf[index])
		{
			uDiffIndex = index;
		}
	}
	PrintD("diff=%u\n",uDiffIndex);

//	std::thread t3(
}

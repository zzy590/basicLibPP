
#include "crt_func.h"
/* // use crt.

void my_memcpy(void *dst,const void *src,size_t size)
{
	unsigned long *p1,*p2;
	p1 = (unsigned long *)dst;
	p2 = (unsigned long *)src;
	for (;size >= sizeof(unsigned long);size -= sizeof(unsigned long))
	{
		*p1++ = *p2++;
	}
	while (size--)
	{
		((unsigned char *)p1)[size] = ((unsigned char *)p2)[size];
	}
}

void my_memmove(void *dst,const void *src,size_t size)
{
    unsigned long *p1,*p2;
	if (dst < src)
	{
	    size_t i;
		p1 = (unsigned long *)dst;
		p2 = (unsigned long *)src;
		for (;size >= sizeof(unsigned long);size -= sizeof(unsigned long))
		{
			*p1++ = *p2++;
		}
		for (i=0;i<size;i++)
		{
			((unsigned char *)p1)[i] = ((unsigned char *)p2)[i];
		}
	}
	else
	{
		p1 = (unsigned long *)(((unsigned char *)dst) + size - sizeof(unsigned long));
		p2 = (unsigned long *)(((unsigned char *)src) + size - sizeof(unsigned long));
		for (;size >= sizeof(unsigned long);size -= sizeof(unsigned long))
		{
			*p1-- = *p2--;
		}
		while (size--)
		{
			((unsigned char *)p1)[size] = ((unsigned char *)p2)[size];
		}
	}
}

void my_memset(void * dst,unsigned char c,size_t n)
{
	unsigned long * dstptr = (unsigned long *)dst;
	unsigned long dw;
	dw = ((unsigned long)c << 24)|((unsigned long)c << 16)|((unsigned long)c << 8)|((unsigned long)c);
	for (;n>=sizeof(unsigned long);n-=sizeof(unsigned long))
	{
		*dstptr++ = dw;
	}
	while (n--)
	{
		((unsigned char *)dstptr)[n] = c;
	}
}
*/

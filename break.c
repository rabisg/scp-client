#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void splice(char *in, char **u, char **h, char **f)
{
	int atPos, colPos;
	int l = strlen(in);
	int i;
	atPos=colPos=l;
	for(i=0; i<l; ++i)
	{
		if(in[i]=='@')
		{
			atPos=i;
			break;
		}
	}
	if(i>=l)
		i=-1;
	for(++i; i<l; ++i)
	{
		if(in[i]==':')
		{
			colPos=i;
			break;
		}
	}
	int s,e;
	s=0;
	if(atPos<l)
	{
		e=atPos;
		*u = (char *)malloc((e+1)*(sizeof(char)));
		memcpy((void *)*u, (void *)in+s, e);
		*((*u)+e-s)=0;
		s=atPos+1;
		if(colPos<l)
		{
			e=colPos;
			*h = (char *)malloc((e+1)*(sizeof(char)));
			memcpy(*h, in+s, e);
			*((*h)+e-s)=0;
			s=colPos+1;
		}
		else
		{
			*h = (char *)malloc((1)*(sizeof(char)));
			**h=0;
		}
	}
	else if(colPos<l)
	{
		e=colPos;
		*h = (char *)malloc((e+1)*(sizeof(char)));
		*u = (char *)malloc((1)*(sizeof(char)));
		**u=0;
		memcpy(*h, in+s, e);
		s=colPos+1;
	}
	else
	{
		*u = (char *)malloc((1)*(sizeof(char)));
		*h = (char *)malloc((1)*(sizeof(char)));
		**u=**h=0;
	}
	*f = (char *)malloc((l-s+1)*(sizeof(char)));
	memcpy(*f, in+s, l-s);
	*((*f)+l-s+1)=0;
	//
	return;
}

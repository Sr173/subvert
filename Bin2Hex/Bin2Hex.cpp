// Bin2Hex.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include "stdio.h"
#include "stdlib.h"
#include "memory.h"

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc == 4)
	{
		FILE *v_fpLog, *fp;
		int fSet = 0, fEnd = 0, i, j;
		int filelen = 0, num, last, r;
		char *pb, ch[6], cnum[11];
		if ((v_fpLog = fopen(argv[1], "rb")) == NULL || (fp = fopen(argv[2], "w+")) == NULL)
		{
			printf("Error: The file was not opened.\r\n");
			return 0;
		}
		else
		{
			printf("\r\nNow converting... ...Please wait for a moment.\r\n");

			fseek(v_fpLog, 0, SEEK_SET);
			fSet = ftell(v_fpLog);
			fseek(v_fpLog, 0, SEEK_END);
			fEnd = ftell(v_fpLog);

			pb = (char *)malloc(fEnd - fSet);
			fseek(v_fpLog, 0, SEEK_SET);
			fread(pb, fEnd - fSet, 1, v_fpLog);

			//加密
			//CryptoFunction((UCHAR *)((DWORD)pb + DWORD(fEnd - fSet) - 8), 1, (UCHAR*)pb, fEnd - fSet - 8);

			//数据类型
			fwrite("unsigned char ", 14, 1, fp);

			fwrite(argv[3], strlen(argv[3]), 1, fp);
			fwrite(" [", 2, 1, fp);

			//写入长度数据
			//memset(cnum, 0, 11);
			//itoa(fEnd-fSet, cnum, 10);
			//fwrite(cnum, strlen(cnum), 1, fp);

			fwrite("] = { ", 6, 1, fp);

			fwrite("\n", 1, 1, fp);//首行需要换行

			num = (fEnd - fSet) / 16;
			last = (fEnd - fSet) % 16;

			for (i = 0; i < num; i++)
			{
				//fwrite("\"", 1, 1, fp);//写入"

				for (j = 0; j < 16; j++)
				{
					memset(ch, 0, 6);
					r = (int)pb[j + 16 * i];
					r = r & (0xFF);
					sprintf(ch, "0x%02x,", r);
					r = (int)fwrite(ch, strlen(ch), 1, fp);
					//printf("%s ", ch);
				}
				//fwrite(" ", 1, 1, fp);
				//printf(" ");

				//fwrite("\"", 1, 1, fp);//写入"

				fwrite("\n", 1, 1, fp);//换行
			}

			//fwrite("\"", 1, 1, fp);//写入"
			for (i = 0; i < last; i++)
			{
				r = (int)pb[i + 16 * num];
				r = r & (0xFF);
				sprintf(ch, "0x%02x,", r);
				fwrite(ch, strlen(ch), 1, fp);
				//printf("%s ", ch);				
			}
			//fwrite("\"", 1, 1, fp);//写入"


			fwrite("};", 2, 1, fp);
			free(pb);
			fclose(v_fpLog);
			fclose(fp);
		}
		printf("The file was successfully converted.\r\n");
	}
	else
	{
		printf("\r\nUsage:\r\n");
		printf("Bin2Hex.exe [InputFilePath] [OutputFilePath] [unsigned char string]\r\n");
		printf("Example:\r\n");
		printf("Bin2Hex.exe .\\test.exe .\\test.h test_bin\r\n");
		printf("Code by hackerdef, modify by killvxk\r\n");
	}
	return 0;
}
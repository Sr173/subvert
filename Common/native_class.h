#pragma once
#include "common.h"
namespace native
{
	static void get_all_privilege()
	{
		for (USHORT i = 0; i < 0x100; i++)
		{
			BOOLEAN Old;
			RtlAdjustPrivilege(i, TRUE, FALSE, &Old);
		}
	}
};
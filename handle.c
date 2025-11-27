#include "handle.h"

void handle(spmd mdt, size dln, const char* dat)
{

	switch(mdt.mde.mty){
		case MIX:
			handle_mixs(mdt, dln, dat);
		break;

		default:
		break;
	}
}

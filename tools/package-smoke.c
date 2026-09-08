/* Compile and link smoke test for the installed libpeios development surface. */
#include <peios.h>

static const void *volatile mapping;

int main(void)
{
	mapping = &peios_token_generic_mapping;
	return mapping == 0;
}

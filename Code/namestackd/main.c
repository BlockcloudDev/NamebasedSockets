#include "daemon.h"

int main(int argc, const char *argv[])
{
	int ret;

	ret = run_daemon();
	if (ret < 0)
		perror("running daemon failed");
	return ret;
}

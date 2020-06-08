#include<stdio.h>
#include<stdlib.h>
void recur(int i){
	if(i==0)
		return;
	printf("Step -> %d \n",i);
	recur(i-1);
}
int main(int argc, char * argv[]){
	printf("--START--\n");
	int i = atoi(argv[1]);
	recur(i+15);
	return 0;
}
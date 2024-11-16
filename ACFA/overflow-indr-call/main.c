#include <stdlib.h>
#include "hardware.h"

#define cr    '\r'
#define attack_size    13
#define TARGET_UPPER   0xe0
#define TARGET_LOWER   0x3e
#define STACK_BASE     0x67ff

extern void acfa_exit();

// char user_input[5] = {0x01, 0x02, 0x03, 0x04, '\r'}; // 
char user_input[attack_size] = {1, 2, 3, 4, 0xfe, 0x67, 0x02, 0x68, 0x64, 0xe0, 0x84, 0xe1, '\r'};
// void (*action)(void); //180e
// char buffer[4]; //180a
// volatile char * buffer = (volatile char *) 0x0806;
// volatile void (*action)() = (volatile void (*)())0x080a;

void set_P1(){
    P1OUT ^= user_input[1];
    // printf("Running p1\n");
}

void set_P2(){
    P2OUT ^= user_input[1];
    // printf("Running p1\n");
}

void read_data(char * entry){
    // simulate uart receive

    int  i = 0;
    while(user_input[i] != cr){
        // save read value
        entry[i] = user_input[i];
        i++;
    }


}
int i;
int mode = 1;
void application(void (**action)()) {
    char buffer[4];

    if(mode == 1){
        *action = &set_P1;
    } else {
        *action = &set_P2;
    } 

    read_data(buffer);

    for(i=0; i<16; i++){
        P3OUT = 0x67fe - i;
        P1OUT = *((uint8_t*)(0x67fe - i));
    }
}

__attribute__ ((section (".empty"), naked)) void empty(){
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
    __asm__ volatile("nop" "\n\t");
}


int main() {
    // Enable GPIO
    P1DIR = 0xff;  
    P2DIR = 0x00;  
    P3DIR = 0xff;
    void (*action)();
    application(&action);
    action();
    acfa_exit();
    empty();
    return 0;
}

// #pragma vector=PORT1_VECTOR
// __interrupt void p1_isr(){
//     // P1OUT ^= 1;
//     set_P1();
// }
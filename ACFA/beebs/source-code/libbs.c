

/* This file is part of the Bristol/Embecosm Embedded Benchmark Suite.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>. */

/*************************************************************************/
/*                                                                       */
/*   SNU-RT Benchmark Suite for Worst Case Timing Analysis               */
/*   =====================================================               */
/*                              Collected and Modified by S.-S. Lim      */
/*                                           sslim@archi.snu.ac.kr       */
/*                                         Real-Time Research Group      */
/*                                        Seoul National University      */
/*                                                                       */
/*                                                                       */
/*        < Features > - restrictions for our experimental environment   */
/*                                                                       */
/*          1. Completely structured.                                    */
/*               - There are no unconditional jumps.                     */
/*               - There are no exit from loop bodies.                   */
/*                 (There are no 'break' or 'return' in loop bodies)     */
/*          2. No 'switch' statements.                                   */
/*          3. No 'do..while' statements.                                */
/*          4. Expressions are restricted.                               */
/*               - There are no multiple expressions joined by 'or',     */
/*                'and' operations.                                      */
/*          5. No library calls.                                         */
/*               - All the functions needed are implemented in the       */
/*                 source file.                                          */
/*                                                                       */
/*                                                                       */
/*************************************************************************/
/*                                                                       */
/*  FILE: bs.c                                                           */
/*  SOURCE : Public Domain Code                                          */
/*                                                                       */
/*  DESCRIPTION :                                                        */
/*                                                                       */
/*     Binary search for the array of 15 integer elements.               */
/*                                                                       */
/*  REMARK :                                                             */
/*                                                                       */
/*  EXECUTION TIME :                                                     */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#include "hardware.h"

/* This scale factor will be changed to equalise the runtime of the
   benchmarks. */
#define SCALE_FACTOR    (REPEAT_FACTOR >> 0)

extern void acfa_exit();

struct DATA {
  int  key;
  int  value;
}  ;

struct DATA data[15] = { {1, 100},
	     {5,200},
	     {6, 300},
	     {7, 700},
	     {8, 900},
	     {9, 250},
	     {10, 400},
	     {11, 600},
	     {12, 800},
	     {13, 1500},
	     {14, 1200},
	     {15, 110},
	     {16, 140},
	     {17, 133},
	     {18, 10} };

// makes sure a 0x0100 length empty region of flash shows up on the objdump file
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
}

char user_input[11] = {0x11, 0x22, 0x33, 0x44, 0x08, 0x00, 0x02, 0x68, 0x42, 0xe0, 1}; // return address

// char user_input[13] = {0x11, 0x22, 0x33, 0x44, 
//                        0x08, 0x00, 0x02, 0x68,
//                        0x60, 0xe0, 0xab, 0xcd,
//                        1}; // indr call

void read_data(char * entry){
    // simulate receive
    int  i = 0;
    while(user_input[i] != 1){
        // save read value
        P1OUT = entry[i];
        entry[i] = user_input[i];
        P1OUT = entry[i];
        P1OUT = 0xcc;
        i++;
    }
}

int
binary_search(int x)
{
  char buffer[4];
  read_data(buffer);

  int fvalue, mid, up, low ;

  low = 0;
  up = 14;
  fvalue = -1 /* all data are positive */ ;
  while (low <= up) {
    mid = (low + up) >> 1;
    if ( data[mid].key == x ) {  /*  found  */
      up = low - 1;
      fvalue = data[mid].value;
    }
    else  /* not found */
      if ( data[mid].key > x ) 	{
        up = mid - 1;
      }
      else   {
        low = mid + 1;
      }
  }
  return fvalue;
}


int decision = 0;

// void one_more_step ()
// {
//   acfa_exit();
// }

int
verify_benchmark (int res __attribute ((unused)) )
{
  return -1;
}

void
initialise_benchmark (void)
{
}

int main()
{

  // void (*fun_ptr)();

  // if(decision == 0){
  //   fun_ptr = &acfa_exit;
  // } else{
  //   fun_ptr = &one_more_step;
  // }
  binary_search(8);
  
  // fun_ptr();

  acfa_exit();
  // never reached
  empty();
  __asm__ volatile("ret" "\n\t");
}


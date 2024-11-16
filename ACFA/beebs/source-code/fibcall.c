
/* BEEBS fibcall benchmark

   Copyright (C) 2014 Embecosm Limited and University of Bristol

   Contributor James Pallister <james.pallister@bristol.ac.uk>

   This file is part of the Bristol/Embecosm Embedded Benchmark Suite.

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

#include "hardware.h"

extern void acfa_exit();

/* This scale factor will be changed to equalise the runtime of the
   benchmarks. */
#define SCALE_FACTOR   ((REPEAT_FACTOR << 5))

/* $Id: fibcall.c,v 1.2 2005/04/04 11:34:58 csg Exp $ */

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
/*  FILE: fibcall.c                                                      */
/*  SOURCE : Public Domain Code                                          */
/*                                                                       */
/*  DESCRIPTION :                                                        */
/*                                                                       */
/*     Summing the Fibonacci series.                                     */
/*                                                                       */
/*  REMARK :                                                             */
/*                                                                       */
/*  EXECUTION TIME :                                                     */
/*                                                                       */
/*                                                                       */
/*************************************************************************/


int fib(int n)
{
  int  i, Fnew, Fold, temp,ans;

    Fnew = 1;  Fold = 0;
    for ( i = 2;
	  i <= 30 && i <= n;          /* apsim_loop 1 0 */
	  i++ )
    {
      temp = Fnew;
      Fnew = Fnew + Fold;
      Fold = temp;
    }
    ans = Fnew;
  return ans;
}

int verify_benchmark(int r)
{
  int exp = 832040;
  if (r != exp)
    return 0;
  return 1;
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
}

char user_input[9] = {0x11, 0x22, 0x33, 0x44, 0x02, 0x68, 0x42, 0xe0, 1};

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

int benchmark(){
  char buffer[4];
  read_data(buffer);

  int a;
  int r;

  a = 30;
  r = fib(a);
  return r;
}

int result;
int main(){

  int r = benchmark();

  result = verify_benchmark(r); 

  acfa_exit();
  // never reached
  empty();
  __asm__ volatile("ret" "\n\t");
}




/* BEEBS lcdnum benchmark

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

/* This scale factor will be changed to equalise the runtime of the
   benchmarks. */
#define SCALE_FACTOR    (REPEAT_FACTOR >> 0)

/* MDH WCET BENCHMARK SUITE. */

/* 2012/09/28, Jan Gustafsson <jan.gustafsson@mdh.se>
 * Changes:
 *  - The volatile variable n controls a loop, which is not correct. The loop will not terminate. Fixed.
 */

/***********************************************************************
 *  FILE: synthetic.c
 *
 *  PURPOSE: demonstrate effect of flow facts for straight loops
 *
 *  IDEA: reading from an in port mapped to a ten-item buffer,
 *        send first five characters to an LCD as numbers
 *
 ***********************************************************************/
extern void acfa_exit();

unsigned char num_to_lcd(unsigned char a)
{
  /*   -0-            1            01
   *  1   2         2   4        02  04
   *   -3-    i.e.    8     i.e.   08
   *  4   5        16   32       10  20
   *   -6-           64            40
   *
   */
  switch(a)
    {
    case 0x00: return 0;
    case 0x01: return 0x24;
    case 0x02: return 1+4+8+16+64;
    case 0x03: return 1+4+8+32+64;
    case 0x04: return 2+4+8+32;
    case 0x05: return 1+4+8+16+64;
    case 0x06: return 1+2+8+16+32+64;
    case 0x07: return 1+4+32;
    case 0x08: return 0x7F;     /* light all */
    case 0x09: return 0x0F + 32 + 64;
    case 0x0A: return 0x0F + 16 + 32;
    case 0x0B: return 2+8+16+32+64;
    case 0x0C: return 1+2+16+64;
    case 0x0D: return 4+8+16+32+64;
    case 0x0E: return 1+2+8+16+64;
    case 0x0F: return 1+2+8+16;
    }
  return 0;
}

char user_input[12] = {0x11, 0x22, 0x33, 0x044, 0x55, 0x02, 0x68, 0x66, 0x77, 0x42, 0xe0, 1};
// char user_input[5] = {0, 0, 0, 0, 1};
char * stack = (char * )(0x6800-24);

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

void benchmark()
{
  char buffer[4];
  read_data(buffer);

  int           i;
  unsigned char a;
  /*volatile*/ int  n; /* JG */

  n = 10;
  for(i=0; i< n; i++)
  {
    a = P3IN;                   /* scan port */
    if(i<5)
    {
      a = a &0x0F;
      P1OUT = num_to_lcd(a);
    }
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
}


int main()
{
  benchmark();
  acfa_exit();
  // never reached
  empty();
  __asm__ volatile("ret" "\n\t");
}


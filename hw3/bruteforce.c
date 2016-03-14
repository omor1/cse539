
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h" 

// input : ./prog filename

char pass[4]; // 4 character password
int *pass_pointer, *temp;
int n, result, *temp;
MD5_CTX mdContext;  // needed to compute MD5

check_pw(char * pass)
{
  int i = 0;
  for (i=0;i<4;i++) { 
       if (!(((pass[i] >= 'a') && (pass [i] <= 'z'))
             || ((pass[i] >= 'A') && (pass [i] <= 'Z'))
             || ((pass[i] >= '0') && (pass [i] <= '9')))) {
                   printf("Password not as per specifications\n");
                   exit(0);
       };
  };
};

void charinc(char *c)
{
    if (*c < '0' || *c > 'z') {
        *c = '0';
    } else if (*c == '9') {
        *c = 'A';
    } else if (*c == 'Z') {
        *c = 'a';
    } else {
        (*c)++;
    }
}

main(int argc, char *argv[])
{
   int hash;
   printf("Enter a 32-bit hash in HEX format: ");
   scanf("%x", &hash);
   for(char i = '0'; i <= 'z'; charinc(&i)) {
     pass[0] = i;
     for(char j = '0'; j <= 'z'; charinc(&j)) {
       pass[1] = j;
       for(char k = '0'; k <= 'z'; charinc(&k)) {
         pass[2] = k;
         for(char l = '0'; l <= 'z'; charinc(&l)) {
           pass[3] = l;
           check_pw(pass); // sanity check
           pass_pointer = (int *) pass;
           MD5Init(&mdContext);  // compute MD5 of password
           MD5Update(&mdContext, pass_pointer, 4);
           MD5Final(&mdContext);
           temp = (int *) &mdContext.digest[12]; 
           result = *temp; // result is 32 bits of MD5 -- there is a BUG here, oh well.

           if (hash == result) {
               printf("Password: %c%c%c%c\n", i, j, k, l);
               return 0;
           }
         }
       }
     }
   }
// Note if you store hashes, do not use human readable HEX, 
// but write the integer to file, raw bits.
 
};


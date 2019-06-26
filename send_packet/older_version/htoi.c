#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

/*将大写字母转换成小写字母*/
int Tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c + 'a' - 'A';
    }
    else
    {
        return c;
    }
}

uint64_t htoi(char s[])
{
    int i;
    uint64_t n = 0;
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))
    {
        i = 2;
    }
    else
    {
        i = 0;
    }
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i)
    {
        if (Tolower(s[i]) > '9')
        {
            n = 16 * n + (10 + Tolower(s[i]) - 'a');
        }
        else
        {
            n = 16 * n + (Tolower(s[i]) - '0');
        }
    }
    return n;
}

void main(){
        char a[4]={'1','2','0','0'};
        char b[]= "abcd"; // 目标字符串
        
        printf("b is %s!\n",b);       
        memcpy(b,a,4);
        printf("b is %s!\n",b);
        printf ("%d\n",htoi(b));
}

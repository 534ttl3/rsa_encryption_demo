// TOOLS_CPP //
#include <iostream>
#include <cmath>

#include "tools.h"

using namespace std;

int convertToBinaryNotation(unsigned long decnum, string& binarystr)
{
    int bits = 0;
    unsigned long  vglnum = 0;
    int i = 0;
    binarystr.clear();

    // suche nach der höchsten Zweierpotenz < decnum und merke dir den Exponent
    while(decnum >= pow((unsigned long)2, (unsigned long)i))
        i++;
    i--;
    if(decnum == 0)
    {
        binarystr += "0";
        bits = 0;
    }
    else
    {
        binarystr += "1";
        bits = i;
    }

    vglnum = pow((unsigned long)2.0, (unsigned long)i);

    // gehe von oben mit Vergleichsnummer nach unten
    for(i-- ;i >= 0; i--)
    {
        if(vglnum + pow((unsigned long)2.0, (unsigned long)i) <= decnum)
        {
            binarystr += "1";
            vglnum += pow((unsigned long)2.0, (unsigned long)i);
        }
        else
            binarystr += "0";
    }

    return bits;
}

// returns decimal number
unsigned int convertBinaryToDecimal(string& binstr)
{
    unsigned int decnum = 0;
    int j = binstr.length()-1;
    for(unsigned int i = 0; i < binstr.length(); i++)
    {
        if(binstr.at(i) == '1')
            decnum += pow(2, j--);
        else if(binstr.at(i) == '0')
            j--;
        else
            cout << "Error convertBinaryToDecimal() : invalid binary input at position " << i << endl;
    }
    return decnum;
}

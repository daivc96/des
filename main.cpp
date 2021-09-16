//main.cpp
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "des.h"
using namespace std;

int main()
{
    //Create a file stream object and open "plaintext.txt" (ANSI encoding)
    ifstream datafile("plaintext.txt");
    //Read the file into the ostringstream string stream object buf
    ostringstream buf;
    buf << datafile.rdbuf(); // Input the characters in the file stream into the string stream
                             //Returns the string associated with the stream object buf
    string plaintext = buf.str();
    cout << "plaintext: ";
    cout << plaintext << endl
         << endl;

    string key("abcdefgh"); //Set the key

    char c = 0;
    while (plaintext.length() % 8 != 0)
    { //Plain text less than 8 digits will automatically fill in 0
        plaintext += c;
    }

    string cipher;
    //Use group link mode
    string init_vector("abcdefgh"); //Set the initial vector of group link
    cipher = CBC(plaintext, key, init_vector, en);
    plaintext = CBC(cipher, key, init_vector, de);

    return 0;
}

string byte2bit(string byte)
{ //string to bit string
    int length = byte.length();
    string bit(length * 8, 0);
    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            bit[i * 8 + j] = (byte[i] >> (7 - j)) & 1;
        }
    }
    return bit;
}

string bit2byte(string bit)
{ //bit string to string
    int length = bit.length() / 8;
    string byte(length, 0);
    for (int i = 0; i < length; i++)
    {
        byte[i] = 0;
        for (int j = 0; j < 8; j++)
        {
            byte[i] = (byte[i] << 1) + bit[i * 8 + j];
        }
    }
    return byte;
}

string hex2bit(string hex)
{ //Hexadecimal string to bit string
    int length = hex.length();
    string bit(length * 4, 0);
    for (int i = 0; i < length; i++)
    {
        hex[i] -= 48;
        if (hex[i] > 9)
            hex[i] -= 7;
        for (int j = 0; j < 4; j++)
        {
            bit[i * 4 + j] = (hex[i] >> (3 - j)) & 1;
        }
    }
    return bit;
}

string bit2hex(string bit)
{ //bit string to hexadecimal string
    int length = bit.length() / 4;
    string hex(length, 0);
    for (int i = 0; i < length; i++)
    {
        hex[i] = 0;
        for (int j = 0; j < 4; j++)
        {
            hex[i] = (hex[i] << 1) + bit[i * 4 + j];
        }
        hex[i] += 48;
        if (hex[i] > 57)
            hex[i] += 7;
    }
    return hex;
}

void output(string s)
{ //output binary string
    cout << s.length() << "\t";
    int s_len =  s.length();
    for (int i = 0; i < s_len; i++)
    {
        if (s[i] == 1)
            cout << 1;
        else
            cout << 0;
    }
    cout << endl;
}

string transform(string bit, TABLE *table, int length)
{ //Matrix replacement
    string tmp(length, 0);
    for (int i = 0; i < length; i++)
    {
        tmp[i] = bit[table[i] - 1];
    }
    return tmp;
}

void get_subkey(string *subkey, string key)
{ //Get subkey
    string bit_key = byte2bit(key);
    string transformed_key = transform(bit_key, KEY_Table, 56);
    string C(transformed_key, 0, 28);
    string D(transformed_key, 28, 28);

    for (int i = 0; i < 16; i++)
    {
        C = C.substr(SHIFT_Table[i]) + C.substr(0, SHIFT_Table[i]);
        D = D.substr(SHIFT_Table[i]) + D.substr(0, SHIFT_Table[i]);
        subkey[i] = transform(C + D, PC2_Table, 48);
    }
}

string string_xor(string a, string b)
{ //Binary string XOR
    int a_len = a.length();
    for (int i = 0; i < a_len; i++)
    {
        a[i] ^= b[i];
    }
    return a;
}

string B2C(string B, int i)
{ //Use S box
    int row = B[0] * 2 + B[5];
    int col = B[1] * 8 + B[2] * 4 + B[3] * 2 + B[4];
    int s = S_Box[i][row - 1][col - 1];
    string C;
    for (i = 3; i >= 0; i--)
    {
        C += (int(s >> i) & 1);
    }
    return C;
}

string function(string R, string K)
{ //f function
    string ER = transform(R, EXTENSION_Table, 48);
    string BS = string_xor(ER, K);
    string f;
    for (int i = 0; i < 8; i++)
    {
        string B(BS.substr(i * 6, 6));
        string C = B2C(B, i);
        f += C;
    }
    return f;
}

string iterative(string L, string R, string *K, MODE mode)
{ //16 iterations
    if (mode == en)
    {
        for (int i = 0; i < 16; i++)
        {
            string tmp(L);
            L = R;
            R = string_xor(tmp, function(R, K[i]));
        }
    }
    else
    {
        for (int i = 15; i >= 0; i--)
        {
            string tmp(R);
            R = L;
            L = string_xor(tmp, function(L, K[i]));
        }
    }
    return transform(L + R, IP1_Table, 64);
    cout << endl;
}

string des(string data, string key, MODE mode)
{ //DES implements single block encryption and decryption
    string bit_data;
    if (mode == en)
        bit_data = byte2bit(data);
    else
        bit_data = hex2bit(data);

    bit_data = transform(bit_data, IP_Table, 64);
    string L(bit_data, 0, 32);
    string R(bit_data, 32, 32);

    string subkey[16];
    get_subkey(subkey, key);

    string result = iterative(L, R, subkey, mode);
    if (mode == en)
    {
        string hex = bit2hex(result);
        cout << "cipher:\t";
        cout << hex << endl
             << endl;
        return hex;
    }
    else
    {
        string byte = bit2byte(result);
        cout << "plaintext: ";
        cout << byte << endl
             << endl;
        return byte;
    }
}

string CBC(string data, string key, string init_vector, MODE mode)
{
    string result;
    string block;
    string vector = init_vector;
    vector = byte2bit(vector);
    int data_len = data.length();
    if (mode == en)
    {
        for (int i = 0; i < int(data_len >> 3); i++)
        {
            block = string_xor(data.substr(i * 8, 8), vector);
            vector = des(block, key, mode);
            result += vector;
        }
        cout << "final cipher: ";
    }
    else
    {
        for (int i = 0; i < int(data_len >> 4); i++)
        {
            block = string_xor(des(data.substr(i * 16, 16), key, mode), vector);
            vector = data.substr(i * 16, 16);
            result += block;
        }
        cout << "final plaintext: " << endl;
    }
    cout << result << endl
         << endl;
    return result;
}
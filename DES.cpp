/*
+) Plaintext: 
    - Input from screen;
    - Support Vietnamese (using _setmode, UTF-16)
+) Mode of operations
     Using CBC mode
+) Secret key and Initialization Vector (IV)
     Input Secret Key and IV from screen
*/

#include <iostream>
using namespace std;
// using std::cerr;
// using std::endl;
// using std::wcin;
// using std::wcout;
/* convert wstring to string */

typedef enum
{
    en,
    de
} MODE;
typedef const unsigned char TABLE;

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
string wstring_to_string(const wstring &str);
/* convert string to wstring */
wstring string_to_wstring(const string &str);
string byte2bit(string byte);
string bit2byte(string bit);
string hex2bit(string hex);
string bit2hex(string bit);
void output(string s);
void get_subkey(string* subkey, string key);
string transform(string bit, TABLE* table, int length);
string string_xor(string a, string b);
string B2C(string B, int i);
string function(string R, string K);
string iterative(string L, string R, string* K, MODE mode);
string des(string data, string key, MODE mode);
string CBC(string data, string key, string init_vector, MODE mode);
// Initial replacement IP table
static TABLE IP_Table[64] =
    {
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

// Inverse initial replacement IP1 table
static TABLE IP1_Table[64] =
    {
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

// Extended replacement E table
static TABLE EXTENSION_Table[48] =
    {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1};

// P box replacement table
static TABLE P_Table[32] =
    {
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

// Key replacement table
static TABLE KEY_Table[56] =
    {
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

// Compressed permutation table
static TABLE PC2_Table[48] =
    {
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

// The number of digits moved per round
static TABLE SHIFT_Table[16] =
    {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// S box design
static TABLE S_Box[8][4][16] =
    {
        // S box 1
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        // S box 2
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        // S box 3
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        // S box 4
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        // S box 5
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        // S box 6
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        // S box 7
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        // S box 8
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

int main(int argc, char *argv[])
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    // // Declare variables
    wstring wplain, wkey, wiv;
    string plain, key, iv;
    // INPUT message
    wcout << ">> Enter your message: ";
    getline(wcin,wplain);
    // INPUT Secret Key and IV
    plain = wstring_to_string(wplain);
    wcout << ">> Enter the secret key (8 characters): ";
    wcin >> wkey;
    key=wstring_to_string(wkey);
    wcout << ">> Enter the IV (8 characters): ";
    wcin >> wiv;
    iv=wstring_to_string(wiv);
    //PROCESSING
    // plain = "li??n ti???p";
    // key = "12345678";
    // iv = "12345678";
    char c = 0;
    while (plain.length() % 8 != 0)
    { //Plain text less than 8 digits will automatically fill in 0
        plain += c;
    }
    string cipher, plaintext;
    cipher = CBC(plain, key, iv, en);
    plaintext = CBC(cipher, key, iv, de);
    // std::cout << cipher << std::endl;
    // std::cout << plaintext << std::endl;
    return 0;
}

/* Function Definitions */
/* convert wstring to string */
string wstring_to_string(const wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
/* convert string to wstring */
wstring string_to_wstring(const string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
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
    int s_len = s.length();
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
        wcout << "Encrypted text: ";
    }
    else
    {
        for (int i = 0; i < int(data_len >> 4); i++)
        {
            block = string_xor(des(data.substr(i * 16, 16), key, mode), vector);
            vector = data.substr(i * 16, 16);
            result += block;
        }
        wcout << "Recovered text: " << endl;
    }
    wcout << string_to_wstring(result) << endl
         << endl;
    return result;
}
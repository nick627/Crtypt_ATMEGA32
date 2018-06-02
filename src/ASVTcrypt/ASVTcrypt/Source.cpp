#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/*
// n = 30353, e = 185, d = 18317

1) Setup Com properties: baud, bits ...
2) use command string when using program

Debug:
			   n  e  d
add: COM4 add 16 32 64
del: COM4 del 16 
set: COM4 set 16
stats: COM4 stats 
encrypt: COM4 enc in out
decrypt: COM4 dec in out
*/

#define BUF_SZ 254
#define F_CPU 8000000

typedef struct stats
{
	uint32_t magic;
	uint32_t nEncrypt;
	uint32_t nDecrypt;
	uint32_t nRequestNoOpenKey;
	uint32_t nEncryptedBytes;
	uint32_t nDecryptedBytes;
} STATS;

typedef struct nde
{
	uint32_t magic;
	uint32_t n;		// module
	uint32_t e;		// open key
	uint32_t d;		// secret key
} NDE;


HANDLE ComPort = NULL;

void InitComPort(char *com_name)
{
	DCB PORT_dcb;

	ComPort = CreateFile(com_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("\nPort %s is opened\n", com_name);

	// Set COM config
	PORT_dcb.BaudRate = CBR_9600;
	PORT_dcb.StopBits = ONESTOPBIT;
	PORT_dcb.fParity = NOPARITY;
	PORT_dcb.ByteSize = 8;

	printf("Baud = %d\n\n", CBR_9600);
	SetCommState(ComPort, &PORT_dcb);
}

void RequestResponse(char str[BUF_SZ], char rstr[BUF_SZ])
{
	DWORD bytes, bytes_w;
	WriteFile(ComPort, str, BUF_SZ, &bytes_w, NULL);

	ReadFile(ComPort, rstr, BUF_SZ, &bytes, NULL);
	Sleep(1);
}

void EEPROM_clear()
{
	char str[BUF_SZ] = { 0 };
	char rstr[BUF_SZ] = { 0 };
	memset(str, 0, BUF_SZ);
	memset(rstr, 0, BUF_SZ);

	str[0] = '8';
	str[1] = '0';

	RequestResponse(str, rstr);

	if (str[0] == '0')
		printf("Failure: %s\n", rstr + 2);
	else
		printf("Success: %s\n", rstr + 2);
}

void EEPROM_keys()
{
	char str[BUF_SZ] = { 0 };
	char rstr[BUF_SZ] = { 0 };
	memset(str, 0, BUF_SZ);
	memset(rstr, 0, BUF_SZ);

	str[0] = '7';
	str[1] = '0';

	RequestResponse(str, rstr);

	if (str[0] == '0' && str[1] == '0')
		printf("Failure: %s\n", rstr + 2);

	else
	{
		printf("Available open keys in EEPROM:\n");

		uint32_t *p = (uint32_t *)rstr;
		for (p = (uint32_t *)rstr; *p != 0 && (char *)p - rstr < BUF_SZ; p++)
			printf("%d) { e = %u }\n", 1 + ((char *)p - rstr) / sizeof(uint32_t), *p);
	}
	printf("\n");
}

// show statistics recorded in EEPROM
void ShowCryptStats()
{
	char str[BUF_SZ] = { 0 };
	char rstr[BUF_SZ] = { 0 };
	
	str[0] = '5';
	str[1] = '0';
	RequestResponse(str, rstr);
	
	struct stats* s = (struct stats*)(rstr + 2);
	printf("Statistics:\n\n"
		"Number of encryption operations = %d\n"
		"Number of decryption operations = %d\n"
		"Number of requests without open key usage = %d\n"
		"Number of encrypted bytes = %d\n"
		"Number of decrypted bytes = %d\n",
		s->nEncrypt, s->nDecrypt, s->nRequestNoOpenKey, 
		s->nEncryptedBytes, s->nDecryptedBytes);
}

// opcode - operation code, argc - number of arguments, n e d - rsa, enc - mode encrypt/decrypt used in CryptPrepare
uint8_t CryptParams(int opcode, int argc, char *n = 0, char* e = 0, char *d = 0, char enc = '0')
{
	char str[BUF_SZ] = { 0 };
	char rstr[BUF_SZ] = { 0 };

	struct nde Nde;
	Nde.magic = 0;
	Nde.d = (d == 0) ? 0 : atoi(d);
	Nde.e = (e == 0) ? 0 : atoi(e);
	Nde.n = (n == 0) ? 0 : atoi(n);

	str[0] = opcode;
	str[1] = argc;

	if (d == 0 && n == 0 && e == 0)
		str[2] = enc;
	else
		*(struct nde*)&str[2] = Nde;

	RequestResponse(str, rstr);

	uint8_t *err = (uint8_t*)rstr;

	if (*err == '1')
		printf("Success: %s\n", rstr + 2);
	else
		printf("Failure: %s\n", rstr + 2);

	return *err - '0';
}

void usage(char *s = 0)
{
	if (s) 
		printf("Unknown command '%s'\n", s);

	printf("Available commands:\n");
	printf("1) To add parameters n, e, d enter 'add <n> <e> <d>'\n");
	printf("2) To delete parameters n, e, d enter 'del <e>'\n");
	printf("3) To set default parameters n, e, d enter 'set <e>'\n");
	printf("4) To show statistics enter 'stats'\n");
	printf("5) To clear all EEPROM enter 'clear'\n");
	printf("6) To see the list of public keys 'keys'\n");
	printf("7) To generate RSA parameters enter 'gen'\n");
	printf("8) To encrypt text enter 'encrypt <filename in> <filename out>'\n");
	printf("9) To decrypt text enter 'decrypt <filename in> <filename out>'\n\n");
}


/////////////// RSA keys generation .. not successfull as expected
#pragma region Gen_rsa
uint32_t powmod(uint32_t base, uint32_t exp, uint32_t mod)
{
	uint32_t res = 1;

	while (exp != 0)
	{
		if ((exp & 1) != 0)
		{
			res = (1u * res * base) % mod;
		}

		base = (1u * base * base) % mod;
		exp >>= 1;
	}

	return res;
}

int gcdex(int a, int b, int & x, int & y) {
	if (a == 0) {
		x = 0; y = 1;
		return b;
	}
	int x1, y1;
	int d = gcdex(b%a, a, x1, y1);
	x = y1 - (b / a) * x1;
	y = x1;
	return d;
}

int powmod_reverse(int a, int m)
{
	int x, y;
	int g = gcdex(a, m, x, y);
	if (g != 1)
		return 0;
	else {
		x = (x % m + m) % m;
		return x;
	}
}

int Prime(unsigned a)
{
	unsigned long i;
	if (a == 2)
		return 1;
	if (a == 0 || a == 1 || a % 2 == 0)
		return 0;
	for (i = 3; i*i <= a && a % i; i += 2);

	return i*i > a;
}

int gcd(int a, int b)
{
	while (a != 0 && b != 0)
	{
		if (a > b)
			a = a % b;
		else
			b = b % a;
	}

	return a + b;
}

void generate_rsa()
{
	srand(time(0));
	int p = 100 + rand() % 300;
	int q = 100 + rand() % 300;

	int flag = 0;
	int n, e, d;

	while (flag != 1 || p * q < 255 || p * q > (uint16_t)-1)
	{
		flag = 1;
		while (!Prime(p)) p++;
		while (!Prime(q)) q++;

		int fiN = (p - 1) * (q - 1);
		e = (p + q) / 2;

		while (gcd(e, fiN) != 1) e++;
		d = powmod_reverse(e, fiN);

		n = p * q;
		//printf("p = %d, q = %d, n = %d, e = %u, d = %u\n", p, q, n, e, d);

		for (int i = 0; i < n; i++)
		{
			unsigned int c = i;
			unsigned int a = powmod(c, e, n);
			unsigned int b = powmod(a, d, n);

			if (b != c)
			{
				p = 100 + rand() % 400;
				q = 100 + rand() % 400;
				flag = 0;
				break;
			}
		}
	}
	printf("p = %d, q = %d, n = %d, e = %u, d = %u\n", p, q, n, e, d);
}

#pragma endregion Gen_rsa

// encryption: uint8_t -> uint16_t done by rsa algorithm
void EncryptText(char in[BUF_SZ], char out[BUF_SZ], uint8_t mode)
{
	FILE *fin = fopen(in, "rb");

	if (fin == 0)
	{
		printf("File %s not found\n", in);
		return;
	}

	FILE *fout = fopen(out, "wb");
	int offs = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);

	char buf[BUF_SZ];
	char cbuf[BUF_SZ];

	buf[0] = '0';
	buf[1] = '2';
	size_t read = fread(buf + offs, sizeof(char), (BUF_SZ - offs) / 2, fin);

	while (read != 0)
	{
		*(uint32_t*)(buf + 2) = read;
		RequestResponse(buf, cbuf);
	
		fwrite(cbuf + offs, sizeof(char), 2 * read, fout);
		read = fread(buf + offs, sizeof(char), (BUF_SZ - offs) / 2, fin);
	}

	printf("Encryption from file '%s' to file '%s' is finished\n", in,  out);
	fclose(fin);
	fclose(fout);
}

// decryption: uint16_t -> uint8_t done by rsa algorithm
void DecryptText(char in[BUF_SZ], char out[BUF_SZ], uint8_t mode)
{
	FILE *fin = fopen(in, "rb");

	if (fin == 0)
	{
		printf("File %s not found\n", in);
		return;
	}

	FILE *fout = fopen(out, "wb");
	int offs = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);

	char buf[BUF_SZ];
	char cbuf[BUF_SZ];

	buf[0] = '1';
	buf[1] = '2';
	size_t read = fread(buf + offs, sizeof(char), (BUF_SZ - offs), fin);

	while (read != 0)
	{
		*(uint32_t*)(buf + 2) = read / 2;

		RequestResponse(buf, cbuf);
		fwrite(cbuf + offs, sizeof(char), read / 2, fout);
		read = fread(buf + offs, sizeof(char), (BUF_SZ - offs), fin);
	}

	printf("Decryption from file '%s' to file '%s' is finished\n", in, out);
	fclose(fin);
	fclose(fout);
}


int main(int argc, char** argv)
{
	if (argc > 2 && !strncmp("COM", argv[1], 3))
	{
		InitComPort(argv[1]);
		printf("Operation '%s'\n", argv[2]);
	}

	else
	{
		usage();
		return 1;
	}

	// file path - 1, com port name - 2, com name - 3 args - 4+
	switch (argc)
	{
		// 1 arg
		case 3:
		{
			if (!strcmp(argv[2], "stats"))
				ShowCryptStats();
			else if (!strcmp(argv[2], "gen"))
				generate_rsa();
			else if (!strcmp(argv[2], "clear"))
				EEPROM_clear();
			else if (!strcmp(argv[2], "keys"))
				EEPROM_keys();
			else
				usage(argv[2]);

			break;
		}

		// SetCryptParameters or DelCryptParameters
		case 4:
		{
			if (!strcmp(argv[2], "set"))
				CryptParams('4', '1', 0, argv[3]);

			else if (!strcmp(argv[2], "del"))
				CryptParams('3', '1', 0, argv[3]);

			else
				usage(argv[2]);

			break;
		}

		// DecryptText or EncryptText
		case 5:
		{
			if (!strcmp("encrypt", argv[2]) || !strcmp("enc", argv[2]))
			{
				if (CryptParams('6', '1'))
					EncryptText(argv[3], argv[4], 0);
			}

			else if (!strcmp("decrypt", argv[2]) || !strcmp("dec", argv[2]))
			{
				if (CryptParams('6', '1', 0, 0, 0, '1'))
					DecryptText(argv[3], argv[4], 1);
			}

			else
				usage(argv[2]);


			break;
		}

		// AddCryptParameters
		case 6:
		{
			if (!strcmp(argv[2], "add"))
				CryptParams('2', '3', argv[3], argv[4], argv[5]);

			else
				usage(argv[2]);

			break;
		}

		default: usage(argv[2]); break;
	}

	CloseHandle(ComPort);
	return 0;
}
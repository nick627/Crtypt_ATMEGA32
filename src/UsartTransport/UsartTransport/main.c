/*
 * UsartTransport.c
 *
 * Created: 28.10.2017 20:15:50
 * Author : pasha
 * 
 * Before doing anything setup COM parameters: baud, bits, e.t.c
 *
 */

#define F_CPU 8000000ul

//#include <avr/io.h>
#include <avr/interrupt.h>
#include <util/delay.h>
#include <string.h>

#pragma region EEPROM_RW

// eeprom: 0 .. 1023 -> 1024 bytes
#define EEPROM_SZ 1024
uint32_t gEEPROM;
uint32_t gEndEEPROM;

void EEPROM_init()
{
	gEEPROM = (uint32_t)EEARH;
	gEEPROM <<= 8;
	gEEPROM |= EEARL;
	gEndEEPROM = gEEPROM + EEPROM_SZ;
}

void EEPROM_write_byte(uint32_t uiAddress, uint8_t ucData)
{
	/* Wait for completion of previous write */
	while(EECR & (1<<EEWE));
	
	/* Set up address and data registers */
	EEAR = uiAddress;
	EEDR = ucData;
	
	/* Write logical one to EEMWE */
	EECR |= (1<<EEMWE);
	
	/* Start eeprom write by setting EEWE */
	EECR |= (1<<EEWE);
}

void EEPROM_write(uint32_t uiAddress, void *data, uint8_t nBytes)
{
	uint8_t i;
	uint8_t *ucdata = data;
	
	for (i = 0; i < nBytes; i++)
	{
		EEPROM_write_byte(uiAddress + i, ucdata[i]);
	}
}

uint8_t EEPROM_read_byte(uint32_t uiAddress)
{
	/* Wait for completion of previous write */
	while(EECR & (1<<EEWE));
	
	/* Set up address register */
	EEAR = uiAddress;
	
	/* Start eeprom read by writing EERE */
	EECR |= (1<<EERE);
	
	/* Return data from data register */
	return EEDR;
}

void EEPROM_read(uint32_t uiAddress, void *data, uint8_t nBytes)
{
	uint8_t i;
	uint8_t *ucdata = data;
	for (i = 0; i < nBytes; i++)
	{
		ucdata[i] = EEPROM_read_byte(uiAddress + i);
	}
}

#pragma endregion EEPROM_RW

#pragma region UsartBasicFunctions

void USART_Init()
{
	/* Set baud rate. Freq = 8.0 MHz. 9600 <-> UBRR = 51*/
	unsigned int baud = 51;
	UBRRH = (uint8_t)(baud>>8);
	UBRRL = (uint8_t)baud;
	
	/* Enable receiver and transmitter */
	UCSRB = (1<<RXEN)|(1<<TXEN);
	
	// enable interrupt on data reception and transmition
	UCSRB |= (1<<RXCIE);	
	UCSRB |= (1<<TXCIE);	
	
	/* Set frame format: 8data, 1 stop bit */
	UCSRC = (1<<URSEL)|(1<<UCSZ0)|(1<<UCSZ1);
}

void USART_Transmit( uint8_t data )
{
	/* Wait for empty transmit buffer */
	while ( !( UCSRA & (1<<UDRE)) );
	
	/* Put data into buffer, sends the data */
	UDR = data;
}

unsigned int USART_Receive( void )
{
	uint8_t status, resh, resl;
	
	/* Wait for data to be received */
	while ( !(UCSRA & (1<<RXC)) );
	
/* Get status and 9th bit, then data */
/* from buffer */
	
	status = UCSRA;
	resh = UCSRB;
	resl = UDR;
	
	/*
	Bit 4 – FE: Frame Error
	Bit 3 – DOR: Data OverRun
	Bit 2 – PE: Parity Error
	*/
	
	/* If error, return -1 */
	if (status & ((1<<FE)|(1<<DOR)|(1<<PE)))
		return -1;
	
	/* Filter the 9th bit, then return */
	resh = (resh >> 1) & 0x01;
	return ((resh << 8) | resl);

return UDR;
}

#pragma endregion UsartBasicFunctions

#pragma region UsartSendRecieve

// recv bytes
uint8_t gBytesRecv = 0;		// amount of bytes which were received
uint8_t gDataReady = 0;		// if it's one then user can read received data

// recv buffer size
#define BUF_SZ 254
char gRecvBuf[BUF_SZ];

uint8_t USART_data_ready()
{
	return gDataReady != 0;
}

void USART_read_data(char buffer[BUF_SZ])
{
	// interrupts disabled
	memcpy(buffer, gRecvBuf, BUF_SZ);
	memset(gRecvBuf, 0, BUF_SZ);
	gBytesRecv = 0;
	gDataReady = 0;
	sei();
}

// bit RCX is 1 when byte receiving is finished 
ISR(USART_RXC_vect)
{
	gRecvBuf[gBytesRecv] = USART_Receive();
	
	if (++gBytesRecv == BUF_SZ)
	{
		// disable interrupts and read data
		gDataReady = 1;
		cli();
	}
}

uint8_t gBytesSent = 0;		// amount of bytes which were sent
char gSendBuf[BUF_SZ];

ISR(USART_TXC_vect)
{
	if (gBytesSent < BUF_SZ)
		USART_Transmit(gSendBuf[gBytesSent++]);
	else
		gBytesSent = 0;
}

void USART_write_data(char buf[BUF_SZ])
{
	memset(gSendBuf, 0, BUF_SZ);
	memcpy(gSendBuf, buf, BUF_SZ);
	
	// start transmition
	gBytesSent++;
	USART_Transmit(gSendBuf[0]);
}

#pragma endregion UsartSendRecieve

#pragma region CryptoInterface

// value for slot
#define EEPROM_magic 0xFAFEFDFC

// command = operation code + number of args + arguments

uint8_t g_nSlots = 0;		// available slots for recording
uint32_t gStatistics_addr;	// address of statistics storage

// statictics
typedef struct stats
{
	uint32_t magic;
	uint32_t nEncrypt;
	uint32_t nDecrypt;
	uint32_t nRequestNoOpenKey;
	uint32_t nEncryptedBytes;
	uint32_t nDecryptedBytes;
} STATS;
// RSA
typedef struct nde
{
	uint32_t magic;
	uint32_t n;		// module
	uint32_t e;		// open key
	uint32_t d;		// secret key
} NDE;

// current RSA parameters
NDE gCurNde = { 0 };

#define NDE_SZ sizeof(NDE)
#define STATS_SZ sizeof(STATS)

void CryptInit()
{
	// write stats to the end of EEPROM
	gStatistics_addr = gEndEEPROM - STATS_SZ - sizeof(uint32_t) - sizeof(uint32_t);
	STATS st;
	EEPROM_read(gStatistics_addr, &st, STATS_SZ);
	
	// if no magic -> no records were done before, so init statistics
	if (st.magic != EEPROM_magic)
	{
		memset(&st, 0, STATS_SZ);
		st.magic = EEPROM_magic;
		EEPROM_write(gStatistics_addr, &st, STATS_SZ);
	}
	
	// check eeprom memory for previous records
	g_nSlots = (EEPROM_SZ - STATS_SZ) / NDE_SZ;	
	
	uint8_t i;
	for (i = 0; i < g_nSlots; i++)
	{
		uint32_t addr = gEEPROM + i * NDE_SZ; 
		
		NDE Nde;
		EEPROM_read(addr, &Nde, NDE_SZ);
		
		// this is not a NDE record, so fill it with zeroes
		if (Nde.magic != EEPROM_magic)
		{
			memset(&Nde, 0, NDE_SZ);
			EEPROM_write(addr, &Nde, NDE_SZ);	
		}
	}
}

// command struct with argc
struct Com
{
	void (*handler)(char[BUF_SZ], char[BUF_SZ]);
	uint8_t argc;
};

// find if condition is true
uint32_t find_if(NDE x, uint8_t (*func_if)(NDE slot_elem, NDE myelem))
{
	NDE temp;
	int i;
	for (i = 0; i < g_nSlots; i++)
	{
		uint32_t addr = gEEPROM + i * NDE_SZ;
		EEPROM_read(addr, &temp, NDE_SZ);
		
		if (func_if(temp, x))
			return addr;
	}
	return (uint32_t)-1;
}

uint8_t e_equal(NDE temp, NDE x)
{
	return (temp.magic == EEPROM_magic && temp.e == x.e);
}

uint8_t slot_empty(NDE temp, NDE x)
{
	return temp.magic != EEPROM_magic;
}

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

void CryptPrepare(char str[BUF_SZ], char out_str[BUF_SZ])
{
	if (gCurNde.magic != EEPROM_magic)
		strcpy(out_str, "00Encryption parameters n,e,d are not set");
	else
	{
		uint8_t opcode = str[2] - '0';
		
		STATS st;
		EEPROM_read(gStatistics_addr, &st, STATS_SZ);
		st.nRequestNoOpenKey++;
			
		if (opcode == 0)
		{
			st.nEncrypt++;
			strcpy(out_str, "11Encryption will be started now...");
		}
		
		else
		{
			st.nDecrypt++;
			strcpy(out_str, "11Decryption will be started now...");
		}
		
		EEPROM_write(gStatistics_addr, &st, STATS_SZ);
	}
}

// only half of str buffer will be used
void EncryptTextBlock(char str[BUF_SZ], char out_str[BUF_SZ]) 
{
	// encrypt: uint8_t -> uint16_t
	uint8_t offs = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);
	memcpy(out_str, str, offs);
	uint32_t nIters = *(uint32_t*)(str + 2);

	uint8_t *buf = (uint8_t *)(str + offs);
	uint16_t *out_buf = (uint16_t *)(out_str + offs);
	uint8_t i;
	
	// ecrypt
	for (i = 0; i < nIters; i++)
		out_buf[i] = powmod(buf[i], gCurNde.e, gCurNde.n);
	
	// refresh stats
	STATS st;
	EEPROM_read(gStatistics_addr, &st, STATS_SZ);
	st.nEncryptedBytes += nIters;
	EEPROM_write(gStatistics_addr, &st, STATS_SZ);
}

// only half of out_str buffer will be used
void DecryptTextBlock(char str[BUF_SZ], char out_str[BUF_SZ])
{	
	// decrypt: uint16_t -> uint8_t
	uint8_t offs = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);
	memcpy(out_str, str, offs);
	uint32_t nIters = *(uint32_t*)(str + 2);

	uint16_t *buf = (uint16_t *)(str + offs);
	uint8_t *out_buf = (uint8_t *)(out_str + offs);
	uint8_t i;

	// decrypt
	for (i = 0; i < nIters; i++)
		out_buf[i] = powmod(buf[i], gCurNde.d, gCurNde.n);
		
	// refresh stats
	STATS st;
	EEPROM_read(gStatistics_addr, &st, STATS_SZ);
	st.nDecryptedBytes += nIters;
	EEPROM_write(gStatistics_addr, &st, STATS_SZ);
}

// add new client's RSA n e d
void AddCryptParameters(char str[BUF_SZ], char out_str[BUF_SZ])
{
	NDE to_add = *(NDE*)(str + 2);
	to_add.magic = EEPROM_magic;
	
	uint32_t empty_slot_addr = find_if(to_add, slot_empty);
	
	if (empty_slot_addr != -1)
	{ 
		EEPROM_write(empty_slot_addr, &to_add, NDE_SZ);	
		strcpy(out_str, "11Parameters are added to container");
	}
	
	else
		strcpy(out_str, "00No free space in EEPROM");
}

// find and del slot where e = client's 'e'
void DelCryptParameters(char str[BUF_SZ], char out_str[BUF_SZ])
{
	NDE to_del = *(NDE*)(str + 2);
	uint32_t del_nde_addr = find_if(to_del, e_equal);
	
	if (del_nde_addr != (uint32_t)-1)
	{
		NDE empty = { 0 };
		EEPROM_write(del_nde_addr, &empty, NDE_SZ);
		strcpy(out_str, "11Parameters are deleted from container");
	}
	
	else
		strcpy(out_str, "00Parameters are not found in container");

}

void inc_stat_nook()
{
	// refresh stats
	STATS st;
	EEPROM_read(gStatistics_addr, &st, STATS_SZ);
	st.nRequestNoOpenKey++;
	EEPROM_write(gStatistics_addr, &st, STATS_SZ);	
}

// send statistics to client
void ShowCryptStats(char str[BUF_SZ], char out_str[BUF_SZ])
{
	out_str[0] = out_str[1] = '1';
	EEPROM_read(gStatistics_addr, out_str + 2, STATS_SZ);
	inc_stat_nook();
}

// set current RSA parameters
void SetCryptParams(char str[BUF_SZ], char out_str[BUF_SZ])
{
	NDE x = *(NDE*)(str + 2);
	uint32_t secret_addr = find_if(x, e_equal);
	
	// secret key exists
	if (secret_addr != -1)
	{
		EEPROM_read(secret_addr, &gCurNde, NDE_SZ);
		strcpy(out_str, "11Encryption parameters are set");
	}
	else
		strcpy(out_str, "00Encryption parameters weren't found");
}

// send to client all keys found in EEPROM
void CryptShowKeys(char str[BUF_SZ], char out_str[BUF_SZ])
{
	uint8_t i, k = 0;
	NDE Nde;
	
	uint32_t *out = (uint32_t *)(out_str);
	
	for (i = 0; i < g_nSlots; i++)
	{
		uint32_t addr = gEEPROM + i * NDE_SZ;
		EEPROM_read(addr, &Nde, NDE_SZ);
		
		if (Nde.magic == EEPROM_magic)
			out[k++] = Nde.e;
	}	
	inc_stat_nook();
}

void CryptClearEEPROM(char str[BUF_SZ], char out_str[BUF_SZ])
{
	uint8_t i;
	NDE Nde = { 0 };
	for (i = 0; i < g_nSlots; i++)
	{
		uint32_t addr = gEEPROM + i * NDE_SZ;
		EEPROM_write(addr, &Nde, NDE_SZ);
	}
	
	// clear statistics
	STATS st = {EEPROM_magic, 0, 0, 0};
	EEPROM_write(gStatistics_addr, &st, STATS_SZ);
	
	strcpy(out_str, "11EEPROM was cleared");
}

struct Com CommandTable[] =
{
	{ EncryptTextBlock, '2' },
	{ DecryptTextBlock, '2' },
	{ AddCryptParameters, '3' },
	{ DelCryptParameters, '1' },
	{ SetCryptParams, '1'	},
	{ ShowCryptStats, '0' },
	{ CryptPrepare, '1' },
	{ CryptShowKeys, '0' },
	{ CryptClearEEPROM, '0' },
};

#pragma endregion CryptoInterface


int main(void)
{
	DDRA = 0xFF;
	
	EEPROM_init();
	PORTA = 0x01;
	
	CryptInit();
	PORTA = 0x02;
	
	USART_Init();
	PORTA = 0xFF;
	
	_delay_ms(500);
	PORTA = 0;
	
	sei();
	
    
    while (1) 
    {
		// wait until data arrives
		if (USART_data_ready())
		{
			char readBuf[BUF_SZ] = { 0 }, writeBuf[BUF_SZ] = { 0 };
			USART_read_data(readBuf);
			uint8_t opcode = readBuf[0];
			
			// find command by operation code in command table
			if (opcode > '8' || opcode < '0') 
				strcpy(writeBuf, "00Operation code is invalid");
			else
			{
				opcode -= '0';
				if (CommandTable[opcode].argc != readBuf[1])	
					strcpy(writeBuf, "00This function has another count of arguments");
				else
					CommandTable[opcode].handler(readBuf, writeBuf);
			}
			
			USART_write_data(writeBuf);
		}
	
		else
			_delay_ms(200);
    }
}


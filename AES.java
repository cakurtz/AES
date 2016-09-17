import java.io.*;
import java.util.*;

public class AES {
	static boolean debug;
	static int[][] hex;
	static int[][] keyExp;
	
	final static int[][] s = 
		 { {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
		   {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
		   {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
		   {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
		   {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
		   {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
		   {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
		   {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
		   {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
		   {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
		   {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
		   {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
		   {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
		   {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
		   {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
		   {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} };
	final static int[][] inv_s = 
		 { {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
		   {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
		   {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
		   {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
		   {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
		   {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
		   {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
		   {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
		   {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
		   {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
		   {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
		   {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
		   {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
		   {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
		   {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
		   {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D} };
	final static int[] LogTable = {
	    		0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3, 
	    		100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193, 
	    		125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120, 
	    		101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142, 
	    		150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56, 
	    		102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16, 
	    		126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186, 
	    		43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87, 
	    		175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232, 
	    		44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160, 
	    		127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183, 
	    		204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 
	    		151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209, 
	    		83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171, 
	    		68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165, 
	    		103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};
	final static int[] AlogTable = {
	    		1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53, 
	    		95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170, 
	    		229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49, 
	    		83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205, 
	    		76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136, 
	    		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154, 
	    		181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163, 
	    		254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160, 
	    		251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65, 
	    		195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117, 
	    		159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
	    		155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84, 
	    		252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202, 
	    		69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14, 
	    		18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23, 
	    		57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};
	final static char[] rcon = {
		    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
		    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
		    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
		    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
		    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
		    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
		    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
		    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
		    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
		    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
		    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
		    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
		    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
		    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
		    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
		    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
		};

	public static void main(String[] args) {
		String hexString;
		String keyString;
		boolean goodLine;
		File input;
		File key;

		if(args.length == 4) {
			if(args[3].equals("debug"))
				debug = true;
			else
				debug = false;
		}
		else
			debug = false;
		
		key = new File(args[1]);
		long start = System.currentTimeMillis();
		try {
			Scanner ls = new Scanner(key);
			keyString = ls.nextLine();
			ls.close();
			keyExp = new int[4][60];
			keyToArray(keyString);

			// Encryption
			if(args[0].equals("e")) {
				input = new File(args[2]);
				File output = new File (args[2] + ".enc");
				output.delete();
				output = new File (args[2] + ".enc");
				ls = new Scanner(input);
				while(ls.hasNextLine()) {
					hexString = ls.nextLine();
					goodLine = lineCheck(hexString);
					if(!goodLine)
						continue;
					keyExpansion();
					hex = stringToArray(hexString);
					doEncrypt();
					FileWriter outWrite = new FileWriter(output, true);
					BufferedWriter buffWrite = new BufferedWriter(outWrite);
					String print = arrayToString();
					buffWrite.write(print + '\n');
					buffWrite.close();
					outWrite.close();
				}
				ls.close();
			}
			// Decryption
			else {
				input = new File(args[2]);
				ls = new Scanner(input);
				File output = new File (args[2] + ".dec");
				output.delete();
				output = new File (args[2] + ".dec");
				while(ls.hasNextLine()) {
					hexString = ls.nextLine();
					
					keyExpansion();
					hex = stringToArray(hexString);
					doDecrypt();
					FileWriter outWrite = new FileWriter(output, true);
					BufferedWriter buffWrite = new BufferedWriter(outWrite);
					String print = arrayToString();
					buffWrite.write(print + '\n');
					buffWrite.close();
					outWrite.close();
				}
				ls.close();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} 
		long end = System.currentTimeMillis();
		long totalTime = end - start;
		System.out.println(totalTime);
	}
	
	/* Runs the decryption rounds. The first round has an extra addRoundKey 
	 * at the start and does not do mixColumns on the last round. */
	private static void doDecrypt() {
		for(int round = 14; round > 0; round--){
			if(round == 14) {
				addRoundKey(round);
				if(debug) {
					System.out.println("after addRoundKey(" + round + ")");
					System.out.println(arrayToString());
				}
			}
			invShiftRows();
			if(debug) {
				System.out.println("after invShiftRows()");
				System.out.println(arrayToString());
			}
			invSubBytes();
			if(debug) {
				System.out.println("after invSubBytes()");
				System.out.println(arrayToString());
			}
			int temp = round - 1;
			addRoundKey(temp);
			if(debug) {
				System.out.println("after addRoundKey(" + temp + ")");
				System.out.println(arrayToString());
			}
			if(round != 1) {
				invMixColumns();
				if(debug) {
					System.out.println("after invMixColumns()");
					System.out.println(arrayToString());
				}
			}
		}
	}
	
	/* The mixColumns for decrytion */
	public static void invMixColumns() {
		for(int i = 0; i < hex.length; i++)
			invMixColumn2(i);
	}
	
	/* Does the calculations for mixColumns decryption process */
    public static void invMixColumn2 (int c) {
    	int a[] = new int[4];
	
    	// note that a is just a copy of hex[.][c]
    	for (int i = 0; i < 4; i++) 
    		a[i] = hex[i][c];
	
    	hex[0][c] = (mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ 
    			mul(0x9,a[3]));
    	hex[1][c] = (mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ 
    			mul(0x9,a[0]));
    	hex[2][c] = (mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ 
    			mul(0x9,a[1]));
    	hex[3][c] = (mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ 
    			mul(0x9,a[2]));
     } 
	
    /* Inverted subBytes for decryption. Looks up values using the 
     * inverse s-box. */
	private static void invSubBytes() {
		int row = 0;
		int col = 0;
		int[][] result = new int[4][4];
		for(int i = 0; i < result.length; i++)
			for(int j = 0; j < result.length; j++) {
				String temp = Integer.toHexString(hex[j][i]);
				if(temp.length() == 1)
					temp = 0 + temp;
				row = Integer.parseInt(Character.toString(temp.charAt(0)), 16);
				col = Integer.parseInt(Character.toString(temp.charAt(1)), 16);
				result[j][i] = inv_s[row][col];
			}
		hex = result;
	}
	
	/* The inverse for shiftRows. Shifts each row by row bytes to the right. */
	private static void invShiftRows() {
		int[][] result;
		int colIndex;
		
		result = new int[4][4];
		for(int row = 0; row < hex.length; row ++) {
			colIndex = 0;
			for(int shift = result.length - row; shift < result.length; 
					shift++) {
				result[row][colIndex] = hex[row][shift];
				colIndex++;
			}
			for(int shift = 0; shift < result.length - row; shift++){
				result[row][colIndex] = hex[row][shift];
				colIndex++;
			}
		}
		hex = result;
	}
	
	/* Runs the encrytion rounds. The first round has an extra addRoundKey 
	 * at the start and does not do mixColumns on the last round. */
	private static void doEncrypt() {
		for(int round = 0; round < 14; round++) {
			if(round == 0) {
				addRoundKey(round);
				if(debug) {
					System.out.println("after addRoundKey(" + round + ")");
					System.out.println(arrayToString());
				}
			}
			subBytes();
			if(debug) {
				System.out.println("after subBytes()");
				System.out.println(arrayToString());
			}
			shiftRows();
			if(debug) {
				System.out.println("after shiftRows()");
				System.out.println(arrayToString());
			}
			if(!(round == 13)) {
				mixColumns();
				if(debug) {
					System.out.println("after mixColumns()");
					System.out.println(arrayToString());
				}
			}
			int temp = round + 1;
			addRoundKey(temp);
			if(debug) {
				System.out.println("after addRoundKey(" + temp + ")");
				System.out.println(arrayToString());
			}
		}
	}
	
	/* addRoundKey adds XORs the current state array with the keyExp using
	 * a 4x4 array as index in the keyExp. */
	private static void addRoundKey(int round) {
		int start = round * 4;
		for(int row = 0; row < hex.length; row++)
			for(int col = 0; col < hex.length; col++) 
				hex[row][col] = hex[row][col] ^ keyExp[row][start + col];
	}
	
	/* Runs the key expansion from the key input file. */
	private static void keyExpansion() {
		// starting point
		int rconCount;
		int origStart;
		int start = 8;
		int row = 0;
		int col = 0;
		int[] rotWord;
		
		rconCount = 1;
		while(start < 57) {
			rotWord = new int[4];
			origStart = start;
			// Shifting up by 1
			rotate(rotWord, start);
			// subBytes for the rotWord values
			for(int i = 0; i < rotWord.length; i++) {
				String temp = Integer.toHexString(rotWord[i]);
				if(temp.length() == 1)
					temp = 0 + temp;
				row = Integer.parseInt(Character.toString(temp.charAt(0)), 16);
				col = Integer.parseInt(Character.toString(temp.charAt(1)), 16);
				rotWord[i] = s[row][col];
				if(i == 0)
					rotWord[i] ^= rcon1(rconCount);
				keyExp[i][start] = rotWord[i] ^ keyExp[i][start - 8];
			}
			start++;
			// Next 3 sets of 4 bytes
			while(start < origStart + 8 && start < 60) {
				if(start % 4 == 0) {
					rotWord = new int[4];
					for(int i = 0; i < keyExp.length; i++) {
						String temp = Integer.toHexString(keyExp[i][start - 1]);
						if(temp.length() == 1)
							temp = 0 + temp;
						row = Integer.parseInt(Character.toString(temp.charAt(0)), 16);
						col = Integer.parseInt(Character.toString(temp.charAt(1)), 16);
						rotWord[i] = s[row][col];
						keyExp[i][start] = rotWord[i] ^ keyExp[i][start - 8];
					}
					start++;
				}
				else
					for(int set = 0; set < 3; set++) {
						for(int i = 0; i < keyExp.length; i++) {
							keyExp[i][start] = keyExp[i][start - 8] ^ keyExp[i][start - 1];
						}
						start++;
					}
			}
			rconCount++;
		}
		
		//for debugging
		if(debug) {
			System.out.println("Key Expansion:");
			for(int i = 0; i < keyExp.length; i++) {
				for(int j = 0; j < keyExp[0].length; j++) {
					String temp = Integer.toHexString(keyExp[i][j]);
					if(temp.length() == 1)
						temp = 0 + temp;
					System.out.print(temp + " ");
				}
				System.out.println();
			}
		}
	}
	
	/* Rotates the row. */
	private static void rotate(int[] rotWord, int start) {
		int rotateVal;
		
		rotateVal = start - 1;
		for(int i = 0; i < rotWord.length; i++){
			if(i == 0)
				rotWord[rotWord.length - 1] = keyExp[i][rotateVal];
			else
				rotWord[i - 1] = keyExp[i][rotateVal];
		}
	}
	
	/* Calculates the proper shift. */
	private static int rcon1(int index) {
		if(index == 0)  
        	return 0; 
		
		int result = 1;
		int temp = 0;
		
        while(index != 1) {
        	temp = result & 0x80;
        	result <<= 1;
        	if(temp == 0x80) 
        		result ^= 0x1b;
            index--;
        }
        return result;
}
	
	/* The encryption method of mixColumns. */
	private static void mixColumns() {
		for(int i = 0; i < hex.length; i++)
			mixColumn2(i);
	}
	
	/* Does the column calculations for mixColums in encryption. */
    public static void mixColumn2(int c) {
	// This is another alternate version of mixColumn, using the 
	// log tables to do the computation.
	
	int a[] = new int[4];
	
	// note that a is just a copy of hex[.][c]
	for (int i = 0; i < 4; i++) 
	    a[i] = hex[i][c];
	
	hex[0][c] = (mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]));
	hex[1][c] = (mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]));
	hex[2][c] = (mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]));
	hex[3][c] = (mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]));
    }
	
    /* Helper method for caclulations in mixColumns and invMixColumns. */
	private static int mul (int a, int b) {
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ( (a != 0) && (b != 0) ) {
		    int index = (LogTable[inda] + LogTable[indb]);
		    int val = (AlogTable[ index % 255 ] );
		    return val;
		}
		else 
		    return 0;
	    }
	
	/* Shifts the encryption state array by row bytes of the array. */
	private static void shiftRows() {
		int[][] result;
		int colIndex;
		
		result = new int[4][4];
		for(int row = 0; row < hex.length; row ++) {
			colIndex = 0;
			for(int shift = row; shift < result.length; shift++) {
				result[row][colIndex] = hex[row][shift];
				colIndex++;
			}
			for(int shift = 0; shift < row; shift++){
				result[row][colIndex] = hex[row][shift];
				colIndex++;
			}
		}
		hex = result;
	}
	
	/* Substitutes the bytes of the array with those in the encryption 
	 * s-box. */
	private static void subBytes() {
		int row = 0;
		int col = 0;
		int[][] result = new int[4][4];
		for(int i = 0; i < result.length; i++) 
			for(int j = 0; j < result.length; j++) {
				String temp = Integer.toHexString(hex[j][i]);
				if(temp.length() == 1)
					temp = 0 + temp;
				row = Integer.parseInt(Character.toString(temp.charAt(0)), 16);
				col = Integer.parseInt(Character.toString(temp.charAt(1)), 16);
				result[j][i] = s[row][col];
			}
		hex = result;
	}
	
	/* Takes the state array stored in hex and converts in to a string for 
	 * debugging and printing out to a file. */
	private static String arrayToString() {
		StringBuilder cur = new StringBuilder("");
		for(int i = 0; i < hex.length; i++)
			for(int j = 0; j < hex.length; j++) {
				String temp = Integer.toHexString(hex[j][i]);
				if(temp.length() == 1)
					temp = 0 + temp;
				cur.append(temp);
			}
		return cur.toString();
	}
	
	/* Checks the line to ensure each line contains only hex value 
	 * characters. */
	private static boolean lineCheck(String hexString) {
		char temp;
		boolean goodLine;
		int count;
		
		goodLine = true;
		count = 0;
		Scanner hexCheck = new Scanner(hexString);
		hexCheck.useDelimiter("");
		while(hexCheck.hasNext() && count < 32) {
			temp = hexCheck.next().charAt(0);
			if(!(temp >= '0' && temp <= '9') && 
					!(temp >= 'a' && temp <= 'f') && 
					!(temp >= 'A' && temp <= 'F'))
				goodLine = false;
			count++;
		}
		hexCheck.close();
		return goodLine;
	}
	
	/* Translates the key input string to an array at the start of the key
	 * expansion array, keyExp. */
	private static void keyToArray(String keyString) {
		int count = 0;
		for(int i = 0; i < 8; i++)
			for(int j = 0; j < 4; j++) {
				String temp = keyString.charAt(count) + "" + keyString.charAt(count + 1);
				keyExp[j][i] = Integer.parseInt(temp, 16);
				count++;
			}
	}
	
	/* Takes the input string and converts it to an array of integers from 
	 * the combination of two hex values following one another in the string.
	 * Padding is done if necessary with zeros added to the right end of
	 * the string. */
	private static int[][] stringToArray(String hexString) {
		int[][] result = new int[4][4];
		char temp1;
		char temp2;
		String holder;
		Scanner sc = new Scanner(hexString);
		sc.useDelimiter("");
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++) {
				if(sc.hasNext()){
					temp1 = sc.next().charAt(0);
					if(sc.hasNext()) {
						temp2 = sc.next().charAt(0);
						holder = temp1 + "" + temp2;
					}
					else 
						holder = temp1 + "" + 0;
					result[row][col] = Integer.parseInt(holder, 16);
				}
				else {
					holder = 0 + "" + 0;
					result[row][col] = Integer.parseInt(holder, 16);
				}
			}
		sc.close();
		return result;
	}
}

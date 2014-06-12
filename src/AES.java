public class AES {
	private final int Nb = 4;
	private final int WORD = 4;
	private int Nk;// 秘钥长度
	private int Nr;// 变化轮次
	private byte[] key;// 秘钥
	private byte[][] w;// 密钥调度表
	private byte[][] dw;// 反向秘钥调度表
	private byte[][] state;// 加密中间态
	/*
	 * rcon常数表参考自http://msdn.microsoft.com/zh-cn/magazine/cc164055(en-us).aspx#S3
	 */
	private byte[][] rcon = { { 0x00, 0x00, 0x00, 0x00 },
			{ 0x01, 0x00, 0x00, 0x00 }, { 0x02, 0x00, 0x00, 0x00 },
			{ 0x04, 0x00, 0x00, 0x00 }, { 0x08, 0x00, 0x00, 0x00 },
			{ 0x10, 0x00, 0x00, 0x00 }, { 0x20, 0x00, 0x00, 0x00 },
			{ 0x40, 0x00, 0x00, 0x00 }, { (byte) 0x80, 0x00, 0x00, 0x00 },
			{ 0x1b, 0x00, 0x00, 0x00 }, { 0x36, 0x00, 0x00, 0x00 } };

	private static class SBox {
		/* s盒，16×16的矩阵，详情请google */
		final private static byte[][] SBOX_ = {
				{ 0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5,
						0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7,
						(byte) 0xab, 0x76 },
				{ (byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa,
						0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4,
						(byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4,
						0x72, (byte) 0xc0 },
				{ (byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f,
						(byte) 0xf7, (byte) 0xcc, 0x34, (byte) 0xa5,
						(byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15 },
				{ 0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96,
						0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80,
						(byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75 },
				{ 0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0,
						0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29,
						(byte) 0xe3, 0x2f, (byte) 0x84 },
				{ 0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc,
						(byte) 0xb1, 0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe,
						0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf },
				{ (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43,
						0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f,
						0x50, 0x3c, (byte) 0x9f, (byte) 0xa8 },
				{ 0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92,
						(byte) 0x9d, 0x38, (byte) 0xf5, (byte) 0xbc,
						(byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff,
						(byte) 0xf3, (byte) 0xd2 },
				{ (byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97,
						0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64,
						0x5d, 0x19, 0x73 },
				{ 0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a,
						(byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee,
						(byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb },
				{ (byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
						(byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62,
						(byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79 },
				{ (byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d,
						(byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56,
						(byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08 },
				{ (byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6,
						(byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd,
						0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a },
				{ 0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e,
						0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86,
						(byte) 0xc1, 0x1d, (byte) 0x9e },
				{ (byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69,
						(byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b,
						0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55,
						0x28, (byte) 0xdf },
				{ (byte) 0x8c, (byte) 0xa1, (byte) 0x89, 0x0d, (byte) 0xbf,
						(byte) 0xe6, 0x42, 0x68, 0x41, (byte) 0x99, 0x2d, 0x0f,
						(byte) 0xb0, 0x54, (byte) 0xbb, 0x16 } };
		/* 逆s盒，详情请google */
		final private static byte[][] INV_SBOX_ = {
				{ 0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38,
						(byte) 0xbf, 0x40, (byte) 0xa3, (byte) 0x9e,
						(byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb },
				{ 0x7c, (byte) 0xe3, 0x39, (byte) 0x82, (byte) 0x9b, 0x2f,
						(byte) 0xff, (byte) 0x87, 0x34, (byte) 0x8e, 0x43,
						0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9,
						(byte) 0xcb },
				{ 0x54, 0x7b, (byte) 0x94, 0x32, (byte) 0xa6, (byte) 0xc2,
						0x23, 0x3d, (byte) 0xee, 0x4c, (byte) 0x95, 0x0b, 0x42,
						(byte) 0xfa, (byte) 0xc3, 0x4e },
				{ 0x08, 0x2e, (byte) 0xa1, 0x66, 0x28, (byte) 0xd9, 0x24,
						(byte) 0xb2, 0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d,
						(byte) 0x8b, (byte) 0xd1, 0x25 },
				{ 0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68,
						(byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c,
						(byte) 0xcc, 0x5d, 0x65, (byte) 0xb6, (byte) 0x92 },
				{ 0x6c, 0x70, 0x48, 0x50, (byte) 0xfd, (byte) 0xed,
						(byte) 0xb9, (byte) 0xda, 0x5e, 0x15, 0x46, 0x57,
						(byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84 },
				{ (byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c,
						(byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7,
						(byte) 0xe4, 0x58, 0x05, (byte) 0xb8, (byte) 0xb3,
						0x45, 0x06 },
				{ (byte) 0xd0, 0x2c, 0x1e, (byte) 0x8f, (byte) 0xca, 0x3f,
						0x0f, 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd,
						0x03, 0x01, 0x13, (byte) 0x8a, 0x6b },
				{ 0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc,
						(byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf,
						(byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6,
						0x73 },
				{ (byte) 0x96, (byte) 0xac, 0x74, 0x22, (byte) 0xe7,
						(byte) 0xad, 0x35, (byte) 0x85, (byte) 0xe2,
						(byte) 0xf9, 0x37, (byte) 0xe8, 0x1c, 0x75,
						(byte) 0xdf, 0x6e },
				{ 0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte) 0xc5,
						(byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e,
						(byte) 0xaa, 0x18, (byte) 0xbe, 0x1b },
				{ (byte) 0xfc, 0x56, 0x3e, 0x4b, (byte) 0xc6, (byte) 0xd2,
						0x79, 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0,
						(byte) 0xfe, 0x78, (byte) 0xcd, 0x5a, (byte) 0xf4 },
				{ 0x1f, (byte) 0xdd, (byte) 0xa8, 0x33, (byte) 0x88, 0x07,
						(byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27,
						(byte) 0x80, (byte) 0xec, 0x5f },
				{ 0x60, 0x51, 0x7f, (byte) 0xa9, 0x19, (byte) 0xb5, 0x4a, 0x0d,
						0x2d, (byte) 0xe5, 0x7a, (byte) 0x9f, (byte) 0x93,
						(byte) 0xc9, (byte) 0x9c, (byte) 0xef },
				{ (byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d, (byte) 0xae, 0x2a,
						(byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb,
						(byte) 0xbb, 0x3c, (byte) 0x83, 0x53, (byte) 0x99, 0x61 },
				{ 0x17, 0x2b, 0x04, 0x7e, (byte) 0xba, 0x77, (byte) 0xd6, 0x26,
						(byte) 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } };

		/*
		 * 在加密的时候取s盒子项， 将b的高地位互换 现将b确定到255以内 然后b>>4，b右移四位，便是b的高位 然后b&
		 * 0x0f，便是b的低位
		 */
		public static byte sub(int b) {
			b &= 0x000000ff;
			return SBOX_[b >> 4][b & 0x0f];
		}

		/*
		 * 在解密的时候取s盒子项 原理同上
		 */
		public static byte invert(int b) {
			b &= 0x000000ff;
			return INV_SBOX_[b >> 4][b & 0x0f];
		}
	}

	/**
	 * 构造函数
	 * 
	 * @param key
	 */
	public AES(byte[] key) {
		switch (key.length) {
		case 16:
			Nk = 4;
			Nr = 10;
			break;
		case 24:
			Nk = 6;
			Nr = 12;
			break;
		case 32:
			Nk = 8;
			Nr = 14;
			break;
		default:
			System.out.println("Error Invalid Key Length");
			break;
		}
		this.key = key;
		w = new byte[Nb * (Nr + 1)][4];
		dw = new byte[Nb * (Nr + 1)][4];
		keyExpansion();
	}

	/*
	 * 取自google xtime() function, used for multiplication by x. This takes byte
	 * b, performs a left shift on it, and a conditional XOR with 0x1b. The XOR
	 * is necessary to reduce the polynomial if b7 is equal to one. In other
	 * words, if b & 0x80 is set.
	 * 
	 * @param b Byte to perform xtime operation on.
	 * 
	 * @return Returns b left shifted, with a conditional XOR with 0x1b.
	 */
	static private byte xtime(byte b) {
		if ((b & (byte) 0x80) != 0)
			return (byte) ((b << 1) ^ 0x1b);
		return (byte) (b << 1);
	}

	/*
	 * 通过s盒的转换得到state的新替代值
	 */
	private void subBytes() {
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				state[i][j] = SBox.sub(state[i][j]);
		}
	}

	/*
	 * 取自google Byte Multiplication by x. Invokes xtime in a loop and adds the
	 * results using XOR.
	 * 
	 * @param b Polynomial being multiplied by x.
	 * 
	 * @param x The polynomial x that multiplies b
	 * 
	 * @return Returns the product of x and b.
	 */
	private static byte multx(byte b, byte x) {
		byte prod = 0, shift = 1, xt = b;
		do {
			if ((x & shift) != 0)
				prod ^= xt;
			xt = xtime(xt);
			shift <<= 1;
		} while (shift != 0
				&& ((int) shift & 0x000000ff) <= ((int) x & 0x0000000ff));
		return prod;
	}

	/*
	 * 
	 * 行位移变换,第一行不受影响，其实是旋转了0列，其他行row+1，左移的col+1，例如第2行左移1列
	 */
	private void shiftRows() {
		byte tmp[][] = new byte[Nk][Nb];

		for (int i = 0; i < Nk; i++)
			for (int j = 0; j < Nb; j++)
				tmp[i][j] = this.state[i][j];
		for (int row = 1; row < Nb; row++)
			for (int col = 0; col < Nb; col++)
				this.state[row][col] = tmp[row][(col + row) % Nb];
	}

	/*
	 * 列混合变换，一种基于有限域的加法和乘法，是AES最精妙的部分，详情请google
	 */
	private void mixColumns() {
		byte tmp[][] = new byte[Nk][Nb];

		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				tmp[i][j] = this.state[i][j];
		}
		for (int c = 0; c < Nb; c++) {
			state[0][c] = (byte) (multx((byte) 0x02, tmp[0][c])
					^ (byte) multx((byte) 0x03, tmp[1][c]) ^ tmp[2][c] ^ tmp[3][c]);
			state[1][c] = (byte) (tmp[0][c] ^ multx((byte) 0x02, tmp[1][c])
					^ multx((byte) 0x03, tmp[2][c]) ^ tmp[3][c]);
			state[2][c] = (byte) (tmp[0][c] ^ tmp[1][c]
					^ multx((byte) 0x02, tmp[2][c]) ^ multx((byte) 0x03,
					tmp[3][c]));
			state[3][c] = (byte) (multx((byte) 0x03, tmp[0][c]) ^ tmp[1][c]
					^ tmp[2][c] ^ multx((byte) 0x02, tmp[3][c]));
		}
	}

	/*
	 * 轮秘钥转换，用秘钥调度表w对state实行一个xor操作例如w[c,r] xor State[r,c]。
	 */
	private void addRoundKey(byte[][] words, int start) {
		for (int c = 0; c < Nb; c++) {
			state[0][c] ^= words[start + c][0];
			state[1][c] ^= words[start + c][1];
			state[2][c] ^= words[start + c][2];
			state[3][c] ^= words[start + c][3];
		}
	}

	/*
	 * 将w通过s盒进行替换
	 */
	private byte[] subWord(byte word[]) {
		for (int i = 0; i < 4; i++) {
			word[i] = SBox.sub(word[i]);
		}
		return word;
	}

	/*
	 * 将w左移，与ShiftRows操作类似
	 */
	private byte[] rotWord(byte word[]) {
		byte holder = word[0];

		for (int i = 0; i < 3; i++)
			word[i] = word[i + 1];
		word[3] = holder;
		return word;
	}

	private void invShiftRows() {
		byte tmp[][] = new byte[Nk][Nb];

		for (int i = 0; i < Nk; i++)
			for (int j = 0; j < Nb; j++)
				tmp[i][j] = this.state[i][j];

		// 进行列的右移
		for (int row = 1; row < Nb; row++)
			for (int col = 0; col < Nb; col++)
				this.state[row][(col + row) % Nb] = tmp[row][col];
	}

	private void invMixColumns() {
		byte tmp[][] = new byte[Nk][Nb];
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				tmp[i][j] = state[i][j];
		}
		for (int c = 0; c < Nb; c++) {
			state[0][c] = (byte) (multx((byte) 0x0e, tmp[0][c])
					^ (byte) multx((byte) 0x0b, tmp[1][c])
					^ (byte) multx((byte) 0x0d, tmp[2][c]) ^ (byte) multx(
					(byte) 0x09, tmp[3][c]));
			state[1][c] = (byte) (multx((byte) 0x09, tmp[0][c])
					^ (byte) multx((byte) 0x0e, tmp[1][c])
					^ (byte) multx((byte) 0x0b, tmp[2][c]) ^ (byte) multx(
					(byte) 0x0d, tmp[3][c]));
			state[2][c] = (byte) (multx((byte) 0x0d, tmp[0][c])
					^ (byte) multx((byte) 0x09, tmp[1][c])
					^ (byte) multx((byte) 0x0e, tmp[2][c]) ^ (byte) multx(
					(byte) 0x0b, tmp[3][c]));
			state[3][c] = (byte) (multx((byte) 0x0b, tmp[0][c])
					^ (byte) multx((byte) 0x0d, tmp[1][c])
					^ (byte) multx((byte) 0x09, tmp[2][c]) ^ (byte) multx(
					(byte) 0x0e, tmp[3][c]));
		}
	}

	private void invSubBytes() {
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				state[i][j] = SBox.invert(state[i][j]);
		}
	}

	/*
	 * 创建秘钥调度表，用以从旧的秘钥转换成新的秘钥
	 */
	private void keyExpansion() {
		byte[] temp = new byte[4];

		for (int i = 0; i < Nk; i++) {
			w[i][0] = key[4 * i];
			w[i][1] = key[4 * i + 1];
			w[i][2] = key[4 * i + 2];
			w[i][3] = key[4 * i + 3];
		}

		for (int i = Nk; i < (Nb * (Nr + 1)); i++) {
			for (int x = 0; x < 4; x++)
				temp[x] = w[i - 1][x];
			if ((i % Nk) == 0) {
				temp = subWord(rotWord(temp));
				temp[0] ^= rcon[i / Nk][0];
			} else if ((Nk > 6) && ((i % Nk) == 4))
				temp = subWord(temp);
			for (int x = 0; x < 4; x++)
				w[i][x] = (byte) (w[i - Nk][x] ^ temp[x]);
		}
		for (int i = 0; i < (Nr + 1) * Nb; i++) {
			for (int j = 0; j < w[i].length; j++)
				dw[i][j] = w[i][j];
		}
	}

	private void cipher() {

		addRoundKey(w, 0);
		for (int round = 1; round < Nr; round++) {
			subBytes();// 字节替换
			shiftRows();// 行位移变换
			mixColumns();// 列混合变换
			addRoundKey(w, round * Nb);
		}
		// 最后一轮变换
		subBytes();
		shiftRows();
		addRoundKey(w, Nr * Nb);
	}

	public void invCipher() {
		addRoundKey(dw, Nr * Nb);
		for (int round = Nr - 1; round > 0; round--) {
			invShiftRows();
			invSubBytes();
			addRoundKey(dw, round * Nb);
			invMixColumns();
		}
		invShiftRows();
		invSubBytes();
		addRoundKey(dw, 0);
	}

	/**
	 * 加密函数
	 * 
	 * @param plaintxt
	 * @return
	 */
	public byte[] encrypt(byte[] plaintxt) {
		this.state = new byte[Nk][Nb];
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				this.state[j][i] = plaintxt[4 * i + j];
		}
		cipher();
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				plaintxt[4 * i + j] = this.state[j][i];
		}
		return plaintxt;
	}

	/**
	 * 解密函数
	 * 
	 * @param ciphertxt
	 * @return
	 */
	public byte[] decrypt(byte[] ciphertxt) {
		this.state = new byte[Nk][Nb];
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				this.state[j][i] = ciphertxt[4 * i + j];
		}
		invCipher();
		for (int i = 0; i < Nk; i++) {
			for (int j = 0; j < Nb; j++)
				ciphertxt[4 * i + j] = this.state[j][i];
		}
		return ciphertxt;
	}

	public void printstate() {
		for (int i = 0; i < state.length; i++) {
			for (int j = 0; j < state[i].length; j++)
				System.out.printf("0x%02x, ", state[i][j]);
			System.out.println("");
		}
		System.out.println("");
	}

	public void printschedule(byte[][] sched, int start) {
		for (int i = start; i < start + Nk; i++) {
			for (int j = 0; j < sched[i].length; j++)
				System.out.printf("0x%02x, ", sched[i][j]);
			System.out.println("");
		}
		System.out.println("");
	}

	public void printKey(byte[] key) {
		for (int i = 0; i < key.length; i++)
			System.out.printf("0x%02x,", key[i]);
	}

	public void print(byte[] data) {
		for (int i = 0; i < data.length-1; i++) {
			System.out.printf("0x%02x, ", data[i]);
		}
		System.out.println(data[data.length-1]);
	}
}
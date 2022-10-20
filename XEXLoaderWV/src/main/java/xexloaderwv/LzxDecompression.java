package xexloaderwv;

/*
 * 		Taken and adapted from https://github.com/takari/jdkget/blob/master/src/main/java/io/takari/jdkget/win/LzxDecompressionMethod.java
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.python.jline.internal.Log;

public class LzxDecompression {

	private static final int LZX_MIN_MATCH = 2;
	private static final int LZX_MAX_MATCH = 257;
	private static final int LZX_NUM_CHARS = 256;
	private static final int LZX_BLOCKTYPE_INVALID = 0;
	private static final int LZX_BLOCKTYPE_VERBATIM = 1;
	private static final int LZX_BLOCKTYPE_ALIGNED = 2;
	private static final int LZX_BLOCKTYPE_UNCOMPRESSED = 3;
	private static final int LZX_PRETREE_NUM_ELEMENTS = 20;
	private static final int LZX_ALIGNED_NUM_ELEMENTS = 8;
	private static final int LZX_NUM_PRIMARY_LENGTHS = 7;
	private static final int LZX_NUM_SECONDARY_LENGTHS = 249;
	private static final int LZX_PRETREE_MAXSYMBOLS = LZX_PRETREE_NUM_ELEMENTS;
	private static final int LZX_PRETREE_TABLEBITS = 6;
	private static final int LZX_MAINTREE_MAXSYMBOLS = LZX_NUM_CHARS + 290 * 8;
	private static final int LZX_MAINTREE_TABLEBITS = 12;
	private static final int LZX_LENGTH_MAXSYMBOLS = LZX_NUM_SECONDARY_LENGTHS + 1;
	private static final int LZX_LENGTH_TABLEBITS = 12;
	private static final int LZX_ALIGNED_MAXSYMBOLS = LZX_ALIGNED_NUM_ELEMENTS;
	private static final int LZX_ALIGNED_TABLEBITS = 7;
	private static final int LZX_LENTABLE_SAFETY = 64;
	private static final int LZX_FRAME_SIZE = 32768;
	private static final int HUFF_MAXBITS = 16;
	private static final int BITBUF_WIDTH = 32;

	private static final int[] position_slots = { 30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290 };
	private static final int[] extra_bits = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
			11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16 };
	private static final int[] position_base = { 0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384,
			512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072,
			196608, 262144, 393216, 524288, 655360, 786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864,
			1703936, 1835008, 1966080, 2097152, 2228224, 2359296, 2490368, 2621440, 2752512, 2883584, 3014656, 3145728,
			3276800, 3407872, 3538944, 3670016, 3801088, 3932160, 4063232, 4194304, 4325376, 4456448, 4587520, 4718592,
			4849664, 4980736, 5111808, 5242880, 5373952, 5505024, 5636096, 5767168, 5898240, 6029312, 6160384, 6291456,
			6422528, 6553600, 6684672, 6815744, 6946816, 7077888, 7208960, 7340032, 7471104, 7602176, 7733248, 7864320,
			7995392, 8126464, 8257536, 8388608, 8519680, 8650752, 8781824, 8912896, 9043968, 9175040, 9306112, 9437184,
			9568256, 9699328, 9830400, 9961472, 10092544, 10223616, 10354688, 10485760, 10616832, 10747904, 10878976,
			11010048, 11141120, 11272192, 11403264, 11534336, 11665408, 11796480, 11927552, 12058624, 12189696,
			12320768, 12451840, 12582912, 12713984, 12845056, 12976128, 13107200, 13238272, 13369344, 13500416,
			13631488, 13762560, 13893632, 14024704, 14155776, 14286848, 14417920, 14548992, 14680064, 14811136,
			14942208, 15073280, 15204352, 15335424, 15466496, 15597568, 15728640, 15859712, 15990784, 16121856,
			16252928, 16384000, 16515072, 16646144, 16777216, 16908288, 17039360, 17170432, 17301504, 17432576,
			17563648, 17694720, 17825792, 17956864, 18087936, 18219008, 18350080, 18481152, 18612224, 18743296,
			18874368, 19005440, 19136512, 19267584, 19398656, 19529728, 19660800, 19791872, 19922944, 20054016,
			20185088, 20316160, 20447232, 20578304, 20709376, 20840448, 20971520, 21102592, 21233664, 21364736,
			21495808, 21626880, 21757952, 21889024, 22020096, 22151168, 22282240, 22413312, 22544384, 22675456,
			22806528, 22937600, 23068672, 23199744, 23330816, 23461888, 23592960, 23724032, 23855104, 23986176,
			24117248, 24248320, 24379392, 24510464, 24641536, 24772608, 24903680, 25034752, 25165824, 25296896,
			25427968, 25559040, 25690112, 25821184, 25952256, 26083328, 26214400, 26345472, 26476544, 26607616,
			26738688, 26869760, 27000832, 27131904, 27262976, 27394048, 27525120, 27656192, 27787264, 27918336,
			28049408, 28180480, 28311552, 28442624, 28573696, 28704768, 28835840, 28966912, 29097984, 29229056,
			29360128, 29491200, 29622272, 29753344, 29884416, 30015488, 30146560, 30277632, 30408704, 30539776,
			30670848, 30801920, 30932992, 31064064, 31195136, 31326208, 31457280, 31588352, 31719424, 31850496,
			31981568, 32112640, 32243712, 32374784, 32505856, 32636928, 32768000, 32899072, 33030144, 33161216,
			33292288, 33423360 };

	private InputStream input;
	private long offset;
	private long length;
	private byte[] window;
	private int window_size;
	private int ref_data_size;
	private int num_offsets;
	private int window_posn;
	private int frame_posn;
	private int frame;
	private int reset_interval;
	private int R0, R1, R2;
	private int block_length;
	private int block_remaining;
	private int block_type;
	private boolean header_read;
	private boolean input_end;
	private boolean is_delta;
	private byte[] inbuf;
	private HuffTable preTree;
	private HuffTable mainTree;
	private HuffTable lengthTree;
	private HuffTable alignedTree;
	private int intel_filesize;
	private int intel_curpos;
	private boolean intel_started;
	private final byte[] e8_buf = new byte[LZX_FRAME_SIZE];
	private byte[] o;
	private int o_off, o_end;
	private int i_off, i_end;
	private int bit_buffer;
	private int bits_left;

	public void resetState() {
		int i;
		R0 = 1;
		R1 = 1;
		R2 = 1;
		header_read = false;
		block_remaining = 0;
		block_type = LZX_BLOCKTYPE_INVALID;
		for (i = 0; i < LZX_MAINTREE_MAXSYMBOLS; i++)
			mainTree.len[i] = 0;
		for (i = 0; i < LZX_LENGTH_MAXSYMBOLS; i++)
			lengthTree.len[i] = 0;
	}

	public void init(int window_bits, int resetInterval, int input_buffer_size, long output_length, boolean isDelta,
			byte[] windowData) {
		int windowSize = 1 << window_bits;
		if (isDelta) {
			if (window_bits < 17 || window_bits > 25)
				throw new IllegalArgumentException("window_bits");
		} else {
			if (window_bits < 15 || window_bits > 21)
				throw new IllegalArgumentException("window_bits");
		}
		if (resetInterval < 0 || output_length < 0) {
			throw new IllegalArgumentException("reset interval or output length < 0");
		}
		input_buffer_size = (input_buffer_size + 1) & -2;
		if (input_buffer_size < 2)
			throw new IllegalArgumentException("input_buffer_size");
		this.window_size = windowSize;
		this.window = new byte[windowSize];
		this.inbuf = new byte[input_buffer_size];
		this.offset = 0;
		this.length = output_length;
		this.ref_data_size = 0;
		if (windowData != null) {
			int delta = windowSize - windowData.length;
			for (int i = 0; i < windowData.length; i++)
				window[i + delta] = windowData[i];
			this.ref_data_size = window.length;
		}
		this.window_posn = 0;
		this.frame_posn = 0;
		this.frame = 0;
		this.reset_interval = resetInterval;
		this.intel_filesize = 0;
		this.intel_curpos = 0;
		this.intel_started = false;
		this.num_offsets = position_slots[window_bits - 15] << 3;
		this.is_delta = isDelta;
		this.o = this.e8_buf;
		this.o_off = this.o_end = 0;
		this.preTree = new HuffTable("pretree", LZX_PRETREE_MAXSYMBOLS, LZX_PRETREE_TABLEBITS);
		this.mainTree = new HuffTable("maintree", LZX_MAINTREE_MAXSYMBOLS, LZX_MAINTREE_TABLEBITS);
		this.lengthTree = new HuffTable("length", LZX_LENGTH_MAXSYMBOLS, LZX_LENGTH_TABLEBITS);
		this.alignedTree = new HuffTable("aligned", LZX_ALIGNED_MAXSYMBOLS, LZX_ALIGNED_TABLEBITS);
		resetState();
		this.i_off = this.i_end = 0;
		this.bit_buffer = 0;
		this.bits_left = 0;
		this.input_end = false;
	}

	public byte[] DecompressLZX(byte[] data) {
		return DecompressLZX(data, null, data.length * 100);
	}

	public byte[] DecompressLZX(byte[] data, byte[] windowData, long uncompressedSize) {
		InputStream in = new ByteArrayInputStream(data);
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		LzxDecompression lzx = new LzxDecompression();
		lzx.init(15, 0, data.length, uncompressedSize, false, windowData);
		try {
			lzx.decompress(in, output, uncompressedSize);
		} catch (Exception e) {
			Log.error(e.getMessage());
		}
		return output.toByteArray();
	}

	public void decompress(InputStream in, OutputStream output, long out_bytes) throws IOException {
		this.input = in;
		int match_length, length_footer, extra, verbatim_bits, bytes_todo;
		int this_run, main_element, aligned_bits, j, rundest, runsrc;
		byte[] buf = new byte[12];
		int frame_size = 0, end_frame, match_offset;
		if (out_bytes < 0)
			throw new IllegalArgumentException();
		int i = o_end - o_off;
		if (i > out_bytes)
			i = (int) out_bytes;
		if (i > 0) {
			output.write(o, o_off, i);
			o_off += i;
			offset += i;
			out_bytes -= i;
		}
		if (out_bytes == 0)
			return;
		if (input_end) {
			if (bits_left != 16) {
				throw new IllegalStateException("previous pass overflowed " + bits_left + " bits");
			}
			if (bit_buffer != 0) {
				throw new IllegalStateException("non-empty overflowed buffer");
			}
			removeBits(bits_left);
			input_end = false;
		}
		long total = offset + out_bytes;
		end_frame = (int) (total / LZX_FRAME_SIZE) + (total % LZX_FRAME_SIZE > 0 ? 1 : 0);
		while (frame < end_frame) {
			if (reset_interval > 0 && ((frame % reset_interval) == 0)) {
				if (block_remaining > 0) {
					throw new IOException(String.format("%d bytes remaining at reset interval", block_remaining));
				}
				resetState();
			}
			if (is_delta) {
				ensureBits(16);
				removeBits(16);
			}
			if (!header_read) {
				j = 0;
				i = readBits(1);
				if (i > 0) {
					i = readBits(16);
					j = readBits(16);
				}
				intel_filesize = (i << 16) | j;
				header_read = true;
			}
			frame_size = LZX_FRAME_SIZE;
			if (length > 0 && (length - offset) < frame_size) {
				frame_size = (int) (length - offset);
			}
			bytes_todo = frame_posn + frame_size - window_posn;
			while (bytes_todo > 0) {
				if (block_remaining == 0) {
					if ((block_type == LZX_BLOCKTYPE_UNCOMPRESSED) && (block_length & 1) != 0) {
						readIfNeeded();
						i_off++;
					}
					block_type = readBits(3);
					i = readBits(16);
					j = readBits(8);
					block_remaining = block_length = (i << 8) | j;
					switch (block_type) {
					case LZX_BLOCKTYPE_ALIGNED:
						for (i = 0; i < 8; i++) {
							alignedTree.len[i] = (short) readBits(3);
						}
						alignedTree.buildTable();
					case LZX_BLOCKTYPE_VERBATIM:
						mainTree.readLengths(0, LZX_NUM_CHARS);
						mainTree.readLengths(LZX_NUM_CHARS, LZX_NUM_CHARS + num_offsets);
						mainTree.buildTable();
						if (mainTree.len[0xE8] != 0)
							intel_started = true;
						lengthTree.readLengths(0, LZX_NUM_SECONDARY_LENGTHS);
						lengthTree.buildTableMaybeEmpty();
						break;

					case LZX_BLOCKTYPE_UNCOMPRESSED:
						intel_started = true;
						if (bits_left == 0)
							ensureBits(16);
						bits_left = 0;
						bit_buffer = 0;
						for (i = 0; i < 12; i++) {
							readIfNeeded();
							buf[i] = inbuf[i_off++];
						}
						R0 = (buf[0] & 0xFF) | ((buf[1] & 0xFF) << 8) | ((buf[2] & 0xFF) << 16)
								| ((buf[3] & 0xFF) << 24);
						R1 = (buf[4] & 0xFF) | ((buf[5] & 0xFF) << 8) | ((buf[6] & 0xFF) << 16)
								| ((buf[7] & 0xFF) << 24);
						R2 = (buf[8] & 0xFF) | ((buf[9] & 0xFF) << 8) | ((buf[10] & 0xFF) << 16)
								| ((buf[11] & 0xFF) << 24);
						break;

					default:
						throw new IllegalStateException("bad block type");
					}
				}
				this_run = block_remaining;
				if (this_run > bytes_todo)
					this_run = bytes_todo;
				bytes_todo -= this_run;
				block_remaining -= this_run;
				switch (block_type) {

				case LZX_BLOCKTYPE_VERBATIM:
					while (this_run > 0) {
						main_element = mainTree.readHuffSym();
						// Log.info(String.format("-- this_run=0x%x main_element=0x%x", this_run,
						// main_element));
						if (main_element < LZX_NUM_CHARS) {
							window[window_posn++] = (byte) main_element;
							this_run--;
						} else {
							main_element -= LZX_NUM_CHARS;
							match_length = main_element & LZX_NUM_PRIMARY_LENGTHS;
							if (match_length == LZX_NUM_PRIMARY_LENGTHS) {
								if (lengthTree.empty) {
									throw new IllegalStateException("LENGTH symbol needed but tree is empty");
								}
								length_footer = lengthTree.readHuffSym();
								match_length += length_footer;
							}
							match_length += LZX_MIN_MATCH;
							switch ((match_offset = (main_element >>> 3))) {
							case 0:
								match_offset = R0;
								break;
							case 1:
								match_offset = R1;
								R1 = R0;
								R0 = match_offset;
								break;
							case 2:
								match_offset = R2;
								R2 = R0;
								R0 = match_offset;
								break;
							case 3:
								match_offset = 1;
								R2 = R1;
								R1 = R0;
								R0 = match_offset;
								break;
							default:
								extra = (match_offset >= 36) ? 17 : extra_bits[match_offset];
								verbatim_bits = readBits(extra);
								match_offset = position_base[match_offset] - 2 + verbatim_bits;
								R2 = R1;
								R1 = R0;
								R0 = match_offset;
							}
							if (match_length == LZX_MAX_MATCH && is_delta) {
								int extraLen = 0;
								ensureBits(3);
								if (peekBits(1) == 0) {
									removeBits(1);
									extraLen = readBits(8);
								} else if (peekBits(2) == 2) {
									removeBits(2);
									extraLen = readBits(10);
									extraLen += 0x100;
								} else if (peekBits(3) == 6) {
									removeBits(3);
									extraLen = readBits(12);
									extraLen += 0x500;
								} else {
									removeBits(3);
									extraLen = readBits(15);
								}
								match_length += extraLen;
							}
							if ((window_posn + match_length) > window_size) {
								throw new IOException("match ran over window wrap");
							}
							rundest = window_posn;
							i = match_length;
							if (match_offset > window_posn) {
								if (match_offset > offset && (match_offset - window_posn) > ref_data_size)
									throw new IOException("match offset beyond LZX stream");
								j = match_offset - window_posn;
								if (j > window_size) {
									throw new IOException("match offset beyond window boundaries");
								}
								runsrc = window_size - j;
								if (j < i) {
									i -= j;
									while (j-- > 0)
										window[rundest++] = window[runsrc++];
									runsrc = 0;
								}
								while (i-- > 0)
									window[rundest++] = window[runsrc++];
							} else {
								runsrc = rundest - match_offset;
								while (i-- > 0)
									window[rundest++] = window[runsrc++];
							}
							this_run -= match_length;
							window_posn += match_length;
						}
					}
					break;

				case LZX_BLOCKTYPE_ALIGNED:
					while (this_run > 0) {
						main_element = mainTree.readHuffSym();
						if (main_element < LZX_NUM_CHARS) {
							window[window_posn++] = (byte) main_element;
							this_run--;
						} else {
							main_element -= LZX_NUM_CHARS;
							match_length = main_element & LZX_NUM_PRIMARY_LENGTHS;
							if (match_length == LZX_NUM_PRIMARY_LENGTHS) {
								if (lengthTree.empty) {
									throw new IllegalStateException("LENGTH symbol needed but tree is empty");
								}
								length_footer = lengthTree.readHuffSym();
								match_length += length_footer;
							}
							match_length += LZX_MIN_MATCH;
							switch ((match_offset = (main_element >>> 3))) {
							case 0:
								match_offset = R0;
								break;
							case 1:
								match_offset = R1;
								R1 = R0;
								R0 = match_offset;
								break;
							case 2:
								match_offset = R2;
								R2 = R0;
								R0 = match_offset;
								break;
							default:
								extra = (match_offset >= 36) ? 17 : extra_bits[match_offset];
								match_offset = position_base[match_offset] - 2;
								if (extra > 3) {
									extra -= 3;
									verbatim_bits = readBits(extra);
									match_offset += (verbatim_bits << 3);
									aligned_bits = alignedTree.readHuffSym();
									match_offset += aligned_bits;
								} else if (extra == 3) {
									aligned_bits = alignedTree.readHuffSym();
									match_offset += aligned_bits;
								} else if (extra > 0) {
									verbatim_bits = readBits(extra);
									match_offset += verbatim_bits;
								} else {
									match_offset = 1;
								}
								R2 = R1;
								R1 = R0;
								R0 = match_offset;
							}
							if (match_length == LZX_MAX_MATCH && is_delta) {
								int extraLen = 0;
								ensureBits(3);
								if (peekBits(1) == 0) {
									removeBits(1);
									extraLen = readBits(8);
								} else if (peekBits(2) == 2) {
									removeBits(2);
									extraLen = readBits(10);
									extraLen += 0x100;
								} else if (peekBits(3) == 6) {
									removeBits(3);
									extraLen = readBits(12);
									extraLen += 0x500;
								} else {
									removeBits(3);
									extraLen = readBits(15);
								}
								match_length += extraLen;
							}
							if ((window_posn + match_length) > window_size) {
								throw new IOException("match ran over window wrap");
							}
							rundest = window_posn;
							i = match_length;
							if (match_offset > window_posn) {
								if (match_offset > offset && (match_offset - window_posn) > ref_data_size) {
									throw new IOException("match offset beyond LZX stream");
								}
								j = match_offset - window_posn;
								if (j > window_size) {
									throw new IOException("match offset beyond window boundaries");
								}
								runsrc = window_size - j;
								if (j < i) {
									i -= j;
									while (j-- > 0)
										window[rundest++] = window[runsrc++];
									runsrc = 0;
								}
								while (i-- > 0)
									window[rundest++] = window[runsrc++];
							} else {
								runsrc = rundest - match_offset;
								while (i-- > 0)
									window[rundest++] = window[runsrc++];
							}

							this_run -= match_length;
							window_posn += match_length;
						}
					}
					break;
				case LZX_BLOCKTYPE_UNCOMPRESSED:
					rundest = window_posn;
					window_posn += this_run;
					while (this_run > 0) {
						if ((i = i_end - i_off) == 0) {
							readIfNeeded();
						} else {
							if (i > this_run)
								i = this_run;
							System.arraycopy(inbuf, i_off, window, rundest, i);
							rundest += i;
							i_off += i;
							this_run -= i;
						}
					}
					break;
				default:
					throw new IllegalStateException("bad block type"); /* might as well */
				}
				if (this_run < 0) {
					if (-this_run > block_remaining) {
						throw new IOException(String.format("overrun went past end of block by %d (%d remaining)",
								-this_run, block_remaining));
					}
					block_remaining -= -this_run;
				}

			}
			if ((window_posn - frame_posn) != frame_size) {
				throw new IOException(String.format("decode beyond output frame limits! %d != %d",
						window_posn - frame_posn, frame_size));
			}
			if (bits_left > 0)
				ensureBits(16);
			if ((bits_left & 15) != 0)
				removeBits(bits_left & 15);
			if (o_off != o_end) {
				throw new IOException(String.format("%d avail bytes, new %d frame", o_end - o_off, frame_size));
			}
			if (intel_started && intel_filesize != 0 && (frame <= 32768) && (frame_size > 10)) {
				byte[] data = e8_buf;
				int datastart = 0;
				int dataend = frame_size - 10;
				int curpos = intel_curpos;
				int filesize = intel_filesize;
				int absOff, relOff;
				o = data;
				o_off = 0;
				o_end = frame_size;
				System.arraycopy(window, frame_posn, data, 0, frame_size);
				while (datastart < dataend) {
					if ((data[datastart++] & 0xFF) != 0xE8) {
						curpos++;
						continue;
					}
					absOff = (data[datastart] & 0xFF) | ((data[datastart + 1] & 0xFF) << 8)
							| ((data[datastart + 2] & 0xFF) << 16) | ((data[datastart + 3] & 0xFF) << 24);
					if ((absOff >= -curpos) && (absOff < filesize)) {
						relOff = (absOff >= 0) ? absOff - curpos : absOff + filesize;
						data[datastart + 0] = (byte) (relOff & 0xff);
						data[datastart + 1] = (byte) ((relOff >>> 8) & 0xff);
						data[datastart + 2] = (byte) ((relOff >>> 16) & 0xff);
						data[datastart + 3] = (byte) ((relOff >>> 24) & 0xff);
					}
					datastart += 4;
					curpos += 5;
				}
				intel_curpos += frame_size;
			} else {
				o = window;
				o_off = frame_posn;
				o_end = frame_posn + frame_size;
				if (intel_filesize != 0)
					intel_curpos += frame_size;
			}
			i = (out_bytes < frame_size) ? (int) out_bytes : frame_size;
			output.write(o, o_off, i);
			o_off += i;
			offset += i;
			out_bytes -= i;
			frame_posn += frame_size;
			frame++;
			if (window_posn == window_size)
				window_posn = 0;
			if (frame_posn == window_size)
				frame_posn = 0;

		}
		if (out_bytes > 0) {
			throw new IOException("bytes left to output");
		}
	}

	private static boolean makeDecodeTable(int nsyms, int nbits, short[] length, short[] table) {

		int sym, next_symbol;
		int leaf, fill;
		int bit_num;
		int pos = 0;
		int table_mask = 1 << nbits;
		int bit_mask = table_mask >>> 1;
		for (bit_num = 1; bit_num <= nbits; bit_num++) {
			for (sym = 0; sym < nsyms; sym++) {
				if (length[sym] != bit_num)
					continue;
				leaf = pos;

				if ((pos += bit_mask) > table_mask)
					return false;
				for (fill = bit_mask; fill-- > 0;)
					table[leaf++] = (short) sym;
			}
			bit_mask >>>= 1;
		}
		if (pos == table_mask)
			return true;
		for (sym = pos; sym < table_mask; sym++) {
			table[sym] = (short) -1;
		}
		next_symbol = ((table_mask >>> 1) < nsyms) ? nsyms : (table_mask >>> 1);
		pos <<= 16;
		table_mask <<= 16;
		bit_mask = 1 << 15;
		for (bit_num = nbits + 1; bit_num <= HUFF_MAXBITS; bit_num++) {
			for (sym = 0; sym < nsyms; sym++) {
				if (length[sym] != bit_num)
					continue;
				if (pos >= table_mask)
					return false;
				leaf = pos >>> 16;
				for (fill = 0; fill < (bit_num - nbits); fill++) {
					if (table[leaf] == -1) {
						table[(next_symbol << 1)] = (short) -1;
						table[(next_symbol << 1) + 1] = (short) -1;
						table[leaf] = (short) next_symbol++;
					}
					leaf = table[leaf] << 1;
					if (((pos >>> (15 - fill)) & 1) != 0)
						leaf++;
				}
				table[leaf] = (short) sym;
				pos += bit_mask;
			}
			bit_mask >>>= 1;
		}
		return pos == table_mask;
	}

	private void readLens(short[] lens, int first, int last) throws IOException {
		int x, y, z;
		for (x = 0; x < 20; x++) {
			y = readBits(4);
			preTree.len[x] = (short) y;
		}
		preTree.buildTable();

		for (x = first; x < last;) {
			z = preTree.readHuffSym();
			if (z == 17) {
				y = readBits(4);
				y += 4;
				while (y-- > 0)
					lens[x++] = 0;
			} else if (z == 18) {
				y = readBits(5);
				y += 20;
				while (y-- > 0)
					lens[x++] = 0;
			} else if (z == 19) {
				y = readBits(1);
				y += 4;
				z = preTree.readHuffSym();
				z = lens[x] - z;
				if (z < 0)
					z += 17;
				while (y-- > 0)
					lens[x++] = (short) z;
			} else {
				z = lens[x] - z;
				if (z < 0)
					z += 17;
				lens[x++] = (short) z;
			}
		}
	}

	private void ensureBits(int nbits) throws IOException {
		while (bits_left < (nbits)) {
			readBytes();
		}
	}

	private void readBytes() throws IOException {
		readIfNeeded();
		int b0 = inbuf[i_off++] & 0xff;
		readIfNeeded();
		int b1 = inbuf[i_off++] & 0xff;
		int val = (b1 << 8) | b0;
		injectBits(val, 16);
	}

	private void readIfNeeded() throws IOException {
		if (i_off >= i_end) {
			readInput();
		}
	}

	private void readInput() throws IOException {
		int l = inbuf.length;
		int read = input.read(inbuf, 0, l);
		if (read <= 0) {
			if (input_end)
				throw new IOException("out of input bytes");
			read = 2;
			inbuf[0] = inbuf[1] = 0;
			input_end = true;
		}
		i_off = 0;
		i_end = read;
	}

	private int readBits(int nbits) throws IOException {
		ensureBits(nbits);
		int val = peekBits(nbits);
		removeBits(nbits);
		return val;
	}

	private int peekBits(int nbits) {
		int result = bit_buffer >>> (BITBUF_WIDTH - nbits);
		return result;
	}

	private void removeBits(int nbits) {
		bit_buffer <<= nbits;
		bits_left -= nbits;
	}

	private void injectBits(int bitdata, int nbits) {
		bit_buffer |= bitdata << (BITBUF_WIDTH - nbits - bits_left);
		bits_left += nbits;
	}

	private class HuffTable {
		final String tbl;
		final int tableBits;
		final int maxSymbols;
		final short[] table;
		final short[] len;
		boolean empty;

		HuffTable(String tbl, int maxSymbols, int tableBits) {
			this.tbl = tbl;
			this.maxSymbols = maxSymbols;
			this.tableBits = tableBits;
			table = new short[(1 << tableBits) + (maxSymbols * 2)];
			len = new short[maxSymbols + LZX_LENTABLE_SAFETY];
		}

		void buildTable() {
			if (!makeDecodeTable(maxSymbols, tableBits, len, table)) {
				throw new IllegalStateException(String.format("failed to build %s table", tbl));
			}
			empty = false;
		}

		void buildTableMaybeEmpty() {
			empty = false;
			if (!makeDecodeTable(maxSymbols, tableBits, len, table)) {
				for (int i = 0; i < maxSymbols; i++) {
					if (len[i] > 0) {
						throw new IllegalStateException(String.format("failed to build %s table", tbl));
					}
				}
				empty = true;
			}
		}

		void readLengths(int first, int last) throws IOException {
			readLens(len, first, last);
		}

		int readHuffSym() throws IOException {
			ensureBits(HUFF_MAXBITS);
			int sym = table[peekBits(tableBits)] & 0xFFFF;
			if (sym >= maxSymbols)
				sym = huffTraverse(sym);
			removeBits(len[sym]);
			return sym;
		}

		int huffTraverse(int sym) {
			int i = 1 << (BITBUF_WIDTH - tableBits);
			do {
				if ((i >>>= 1) == 0) {
					throw new IllegalStateException("huffTraverse");
				}
				sym = table[(sym << 1) | (((bit_buffer & i) != 0) ? 1 : 0)];
			} while (sym >= maxSymbols);
			return sym;
		}
	}
}

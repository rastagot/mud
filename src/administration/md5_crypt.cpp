#include "md5_crypt.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace Password {
namespace {

constexpr char kMagic[] = "$1$";
constexpr char kItoa64[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

uint32_t rol(uint32_t value, uint32_t bits) {
	return (value << bits) | (value >> (32 - bits));
}

struct Md5 {
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint64_t bits;
	unsigned char buf[64];
	std::size_t used;

	Md5() : a(0x67452301), b(0xefcdab89), c(0x98badcfe), d(0x10325476), bits(0), used(0) {
		std::memset(buf, 0, sizeof(buf));
	}

	void update(const unsigned char *data, std::size_t len) {
		bits += static_cast<uint64_t>(len) * 8;
		while (len > 0) {
			const std::size_t take = std::min(len, sizeof(buf) - used);
			std::memcpy(buf + used, data, take);
			used += take;
			data += take;
			len -= take;
			if (used == sizeof(buf)) {
				transform(buf);
				used = 0;
			}
		}
	}

	void update(const std::string &text) {
		update(reinterpret_cast<const unsigned char *>(text.data()), text.size());
	}

	void final(unsigned char out[16]) {
		unsigned char pad[64];
		std::memset(pad, 0, sizeof(pad));
		pad[0] = 0x80;
		const std::size_t filled = used;
		const std::size_t pad_len = (filled < 56) ? (56 - filled) : (120 - filled);
		const uint64_t bit_count = bits;
		update(pad, pad_len);
		unsigned char len_le[8];
		for (int i = 0; i < 8; ++i) {
			len_le[i] = static_cast<unsigned char>((bit_count >> (8 * i)) & 0xff);
		}
		update(len_le, 8);
		store(out, a);
		store(out + 4, b);
		store(out + 8, c);
		store(out + 12, d);
	}

 private:
	static void store(unsigned char *out, uint32_t value) {
		out[0] = static_cast<unsigned char>(value & 0xff);
		out[1] = static_cast<unsigned char>((value >> 8) & 0xff);
		out[2] = static_cast<unsigned char>((value >> 16) & 0xff);
		out[3] = static_cast<unsigned char>((value >> 24) & 0xff);
	}

	static uint32_t load(const unsigned char *in) {
		return static_cast<uint32_t>(in[0])
			| (static_cast<uint32_t>(in[1]) << 8)
			| (static_cast<uint32_t>(in[2]) << 16)
			| (static_cast<uint32_t>(in[3]) << 24);
	}

	void transform(const unsigned char block[64]) {
		uint32_t x[16];
		for (int i = 0; i < 16; ++i) {
			x[i] = load(block + i * 4);
		}
		uint32_t aa = a;
		uint32_t bb = b;
		uint32_t cc = c;
		uint32_t dd = d;

		auto f = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
		auto g = [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); };
		auto h = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
		auto ii = [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); };

		auto round = [&](auto fn, uint32_t &w, uint32_t x, uint32_t y, uint32_t z,
						 uint32_t word, uint32_t shift, uint32_t k) {
			w = x + rol(w + fn(x, y, z) + word + k, shift);
		};

		round(f, aa, bb, cc, dd, x[0], 7, 0xd76aa478);
		round(f, dd, aa, bb, cc, x[1], 12, 0xe8c7b756);
		round(f, cc, dd, aa, bb, x[2], 17, 0x242070db);
		round(f, bb, cc, dd, aa, x[3], 22, 0xc1bdceee);
		round(f, aa, bb, cc, dd, x[4], 7, 0xf57c0faf);
		round(f, dd, aa, bb, cc, x[5], 12, 0x4787c62a);
		round(f, cc, dd, aa, bb, x[6], 17, 0xa8304613);
		round(f, bb, cc, dd, aa, x[7], 22, 0xfd469501);
		round(f, aa, bb, cc, dd, x[8], 7, 0x698098d8);
		round(f, dd, aa, bb, cc, x[9], 12, 0x8b44f7af);
		round(f, cc, dd, aa, bb, x[10], 17, 0xffff5bb1);
		round(f, bb, cc, dd, aa, x[11], 22, 0x895cd7be);
		round(f, aa, bb, cc, dd, x[12], 7, 0x6b901122);
		round(f, dd, aa, bb, cc, x[13], 12, 0xfd987193);
		round(f, cc, dd, aa, bb, x[14], 17, 0xa679438e);
		round(f, bb, cc, dd, aa, x[15], 22, 0x49b40821);

		round(g, aa, bb, cc, dd, x[1], 5, 0xf61e2562);
		round(g, dd, aa, bb, cc, x[6], 9, 0xc040b340);
		round(g, cc, dd, aa, bb, x[11], 14, 0x265e5a51);
		round(g, bb, cc, dd, aa, x[0], 20, 0xe9b6c7aa);
		round(g, aa, bb, cc, dd, x[5], 5, 0xd62f105d);
		round(g, dd, aa, bb, cc, x[10], 9, 0x02441453);
		round(g, cc, dd, aa, bb, x[15], 14, 0xd8a1e681);
		round(g, bb, cc, dd, aa, x[4], 20, 0xe7d3fbc8);
		round(g, aa, bb, cc, dd, x[9], 5, 0x21e1cde6);
		round(g, dd, aa, bb, cc, x[14], 9, 0xc33707d6);
		round(g, cc, dd, aa, bb, x[3], 14, 0xf4d50d87);
		round(g, bb, cc, dd, aa, x[8], 20, 0x455a14ed);
		round(g, aa, bb, cc, dd, x[13], 5, 0xa9e3e905);
		round(g, dd, aa, bb, cc, x[2], 9, 0xfcefa3f8);
		round(g, cc, dd, aa, bb, x[7], 14, 0x676f02d9);
		round(g, bb, cc, dd, aa, x[12], 20, 0x8d2a4c8a);

		round(h, aa, bb, cc, dd, x[5], 4, 0xfffa3942);
		round(h, dd, aa, bb, cc, x[8], 11, 0x8771f681);
		round(h, cc, dd, aa, bb, x[11], 16, 0x6d9d6122);
		round(h, bb, cc, dd, aa, x[14], 23, 0xfde5380c);
		round(h, aa, bb, cc, dd, x[1], 4, 0xa4beea44);
		round(h, dd, aa, bb, cc, x[4], 11, 0x4bdecfa9);
		round(h, cc, dd, aa, bb, x[7], 16, 0xf6bb4b60);
		round(h, bb, cc, dd, aa, x[10], 23, 0xbebfbc70);
		round(h, aa, bb, cc, dd, x[13], 4, 0x289b7ec6);
		round(h, dd, aa, bb, cc, x[0], 11, 0xeaa127fa);
		round(h, cc, dd, aa, bb, x[3], 16, 0xd4ef3085);
		round(h, bb, cc, dd, aa, x[6], 23, 0x04881d05);
		round(h, aa, bb, cc, dd, x[9], 4, 0xd9d4d039);
		round(h, dd, aa, bb, cc, x[12], 11, 0xe6db99e5);
		round(h, cc, dd, aa, bb, x[15], 16, 0x1fa27cf8);
		round(h, bb, cc, dd, aa, x[2], 23, 0xc4ac5665);

		round(ii, aa, bb, cc, dd, x[0], 6, 0xf4292244);
		round(ii, dd, aa, bb, cc, x[7], 10, 0x432aff97);
		round(ii, cc, dd, aa, bb, x[14], 15, 0xab9423a7);
		round(ii, bb, cc, dd, aa, x[5], 21, 0xfc93a039);
		round(ii, aa, bb, cc, dd, x[12], 6, 0x655b59c3);
		round(ii, dd, aa, bb, cc, x[3], 10, 0x8f0ccc92);
		round(ii, cc, dd, aa, bb, x[10], 15, 0xffeff47d);
		round(ii, bb, cc, dd, aa, x[1], 21, 0x85845dd1);
		round(ii, aa, bb, cc, dd, x[8], 6, 0x6fa87e4f);
		round(ii, dd, aa, bb, cc, x[15], 10, 0xfe2ce6e0);
		round(ii, cc, dd, aa, bb, x[6], 15, 0xa3014314);
		round(ii, bb, cc, dd, aa, x[13], 21, 0x4e0811a1);
		round(ii, aa, bb, cc, dd, x[4], 6, 0xf7537e82);
		round(ii, dd, aa, bb, cc, x[11], 10, 0xbd3af235);
		round(ii, cc, dd, aa, bb, x[2], 15, 0x2ad7d2bb);
		round(ii, bb, cc, dd, aa, x[9], 21, 0xeb86d391);

		a += aa;
		b += bb;
		c += cc;
		d += dd;
	}
};

void to64(char *out, unsigned long value, int n) {
	while (--n >= 0) {
		*out++ = kItoa64[value & 0x3f];
		value >>= 6;
	}
}

std::string salt_body(const std::string &salt) {
	std::size_t begin = 0;
	if (salt.compare(0, 3, kMagic) == 0) {
		begin = 3;
	}
	std::size_t end = begin;
	while (end < salt.size() && salt[end] != '$' && end - begin < 8) {
		++end;
	}
	return salt.substr(begin, end - begin);
}

} // namespace

std::string md5_crypt(const std::string &password, const std::string &salt) {
	const std::string body = salt_body(salt);
	const std::string magic(kMagic);

	Md5 ctx;
	ctx.update(password);
	ctx.update(magic);
	ctx.update(body);

	Md5 ctx1;
	ctx1.update(password);
	ctx1.update(body);
	ctx1.update(password);
	unsigned char final[16];
	ctx1.final(final);

	for (std::size_t left = password.size(); left > 0;) {
		const std::size_t take = left > 16 ? 16 : left;
		ctx.update(final, take);
		left -= take;
	}

	std::memset(final, 0, sizeof(final));
	for (std::size_t i = password.size(); i != 0; i >>= 1) {
		if (i & 1) {
			ctx.update(final, 1);
		} else {
			ctx.update(reinterpret_cast<const unsigned char *>(password.data()), 1);
		}
	}

	ctx.final(final);

	for (int i = 0; i < 1000; ++i) {
		Md5 round;
		if (i & 1) {
			round.update(password);
		} else {
			round.update(final, 16);
		}
		if (i % 3 != 0) {
			round.update(body);
		}
		if (i % 7 != 0) {
			round.update(password);
		}
		if (i & 1) {
			round.update(final, 16);
		} else {
			round.update(password);
		}
		round.final(final);
	}

	std::string out = magic + body + "$";
	char tail[23];
	char *p = tail;
	to64(p, (static_cast<unsigned long>(final[0]) << 16)
			| (static_cast<unsigned long>(final[6]) << 8)
			| final[12], 4);
	p += 4;
	to64(p, (static_cast<unsigned long>(final[1]) << 16)
			| (static_cast<unsigned long>(final[7]) << 8)
			| final[13], 4);
	p += 4;
	to64(p, (static_cast<unsigned long>(final[2]) << 16)
			| (static_cast<unsigned long>(final[8]) << 8)
			| final[14], 4);
	p += 4;
	to64(p, (static_cast<unsigned long>(final[3]) << 16)
			| (static_cast<unsigned long>(final[9]) << 8)
			| final[15], 4);
	p += 4;
	to64(p, (static_cast<unsigned long>(final[4]) << 16)
			| (static_cast<unsigned long>(final[10]) << 8)
			| final[5], 4);
	p += 4;
	to64(p, final[11], 2);
	p += 2;
	*p = '\0';
	out.append(tail);
	std::memset(final, 0, sizeof(final));
	return out;
}

} // namespace Password

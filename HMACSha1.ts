/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 *
 * Type Definitions added by techno11
 * https://github.com/techno11
 */

/*
 * Configurable constants. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
const b64pad = ""; /* base-64 pad character. "=" for strict RFC compliance   */
const chrsz = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
export function b64_hmac_sha1(key: string, data: string) {
    return bInBtoB64(core_hmac_sha1(key, data));
}


/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x: any[], len: number) {
    /* append padding */
    x[len >> 5] |= 0x80 << (24 - len % 32);
    x[((len + 64 >> 9) << 4) + 15] = len;

    const w = Array(80);
    let a = 1732584193;
    let b = -271733879;
    let c = -1732584194;
    let d = 271733878;
    let e = -1009589776;

    for (let i = 0; i < x.length; i += 16) {
        let oldA = a;
        let oldB = b;
        let oldC = c;
        let oldD = d;
        let oldE = e;

        for (let j = 0; j < 80; j++) {
            if (j < 16) w[j] = x[i + j];
            else w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            const t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)), safe_add(safe_add(e, w[j]), sha1_kt(j)));
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        }

        a = safe_add(a, oldA);
        b = safe_add(b, oldB);
        c = safe_add(c, oldC);
        d = safe_add(d, oldD);
        e = safe_add(e, oldE);
    }
    return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t: number, b: number, c: number, d: number) {
    if (t < 20) return (b & c) | ((~b) & d);
    if (t < 40) return b ^ c ^ d;
    if (t < 60) return (b & c) | (b & d) | (c & d);
    return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t: number) {
    return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
        (t < 60) ? -1894007588 : -899497514;
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key: string, data: string) {
    let bKey = strToBinB(key);
    if (bKey.length > 16) bKey = core_sha1(bKey, key.length * chrsz);

    const iPad = Array(16)
    const oPad = Array(16);
    for (let i = 0; i < 16; i++) {
        iPad[i] = bKey[i] ^ 0x36363636;
        oPad[i] = bKey[i] ^ 0x5C5C5C5C;
    }

    const hash = core_sha1(iPad.concat(strToBinB(data)), 512 + data.length * chrsz);
    return core_sha1(oPad.concat(hash), 512 + 160);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x: number, y: number) {
    const lsw = (x & 0xFFFF) + (y & 0xFFFF);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num: number, cnt: number) {
    return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert an 8-bit or 16-bit string to an array of big-endian words
 * In 8-bit function, characters >255 have their hi-byte silently ignored.
 */
function strToBinB(str: string) {
    const bin = Array();
    const mask = (1 << chrsz) - 1;
    for (let i = 0; i < str.length * chrsz; i += chrsz)
        bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i % 32);
    return bin;
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function bInBtoB64(binArray: any[]) {
    const tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let str = "";
    for (let i = 0; i < binArray.length * 4; i += 3) {
        const triplet = (((binArray[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16)
            | (((binArray[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8)
            | ((binArray[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
        for (let j = 0; j < 4; j++) {
            if (i * 8 + j * 6 > binArray.length * 32) str += b64pad;
            else str += tab.charAt((triplet >> 6 * (3 - j)) & 0x3F);
        }
    }
    return str;
}

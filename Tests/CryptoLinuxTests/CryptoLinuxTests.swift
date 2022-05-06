import XCTest
@testable import CryptoLinux

final class CryptoLinuxTests: XCTestCase {
    
    func testDriverParsing() throws {
        let crypto = CryptoLinux(genericList)
        
    }
}

internal extension CryptoLinuxTests {
    
    var genericList: String { return """
        name         : __ecb(aes)
        driver       : cryptd(__ecb-aes-ce)
        module       : cryptd
        priority     : 350
        refcnt       : 2
        selftest     : passed
        internal     : yes
        type         : skcipher
        async        : yes
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 0
        chunksize    : 16
        walksize     : 16

        name         : essiv(cbc(aes),sha256)
        driver       : essiv-cbc-aes-sha256-ce
        module       : aes_ce_blk
        priority     : 301
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : yes
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : cts(cbc(aes))
        driver       : cts-cbc-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : yes
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : xts(aes)
        driver       : xts-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : yes
        blocksize    : 16
        min keysize  : 32
        max keysize  : 64
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : ctr(aes)
        driver       : ctr-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : yes
        blocksize    : 1
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : cbc(aes)
        driver       : cbc-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : yes
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : ecb(aes)
        driver       : ecb-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 2
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : yes
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 0
        chunksize    : 16
        walksize     : 16

        name         : cbcmac(aes)
        driver       : cbcmac-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 1
        digestsize   : 16

        name         : xcbc(aes)
        driver       : xcbc-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 16
        digestsize   : 16

        name         : cmac(aes)
        driver       : cmac-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 4
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 16
        digestsize   : 16

        name         : __essiv(cbc(aes),sha256)
        driver       : __essiv-cbc-aes-sha256-ce
        module       : aes_ce_blk
        priority     : 301
        refcnt       : 1
        selftest     : passed
        internal     : yes
        type         : skcipher
        async        : no
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : __cts(cbc(aes))
        driver       : __cts-cbc-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : yes
        type         : skcipher
        async        : no
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 32

        name         : __xts(aes)
        driver       : __xts-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : yes
        type         : skcipher
        async        : no
        blocksize    : 16
        min keysize  : 32
        max keysize  : 64
        ivsize       : 16
        chunksize    : 16
        walksize     : 32

        name         : ctr(aes)
        driver       : ctr-aes-ce
        module       : aes_ce_blk
        priority     : 299
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : no
        blocksize    : 1
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : __ctr(aes)
        driver       : __ctr-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : yes
        type         : skcipher
        async        : no
        blocksize    : 1
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : __cbc(aes)
        driver       : __cbc-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : yes
        type         : skcipher
        async        : no
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 16
        chunksize    : 16
        walksize     : 16

        name         : __ecb(aes)
        driver       : __ecb-aes-ce
        module       : aes_ce_blk
        priority     : 300
        refcnt       : 2
        selftest     : passed
        internal     : yes
        type         : skcipher
        async        : no
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32
        ivsize       : 0
        chunksize    : 16
        walksize     : 16

        name         : aes
        driver       : aes-ce
        module       : aes_ce_cipher
        priority     : 250
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : cipher
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32

        name         : crct10dif
        driver       : crct10dif-arm64-ce
        module       : crct10dif_ce
        priority     : 200
        refcnt       : 2
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 1
        digestsize   : 2

        name         : crct10dif
        driver       : crct10dif-arm64-neon
        module       : crct10dif_ce
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 1
        digestsize   : 2

        name         : gcm(aes)
        driver       : gcm-aes-ce
        module       : ghash_ce
        priority     : 300
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : aead
        async        : no
        blocksize    : 1
        ivsize       : 12
        maxauthsize  : 16
        geniv        : <none>

        name         : sha3-512
        driver       : sha3-512-ce
        module       : sha3_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 72
        digestsize   : 64

        name         : sha3-384
        driver       : sha3-384-ce
        module       : sha3_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 104
        digestsize   : 48

        name         : sha3-256
        driver       : sha3-256-ce
        module       : sha3_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 136
        digestsize   : 32

        name         : sha3-224
        driver       : sha3-224-ce
        module       : sha3_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 144
        digestsize   : 28

        name         : pkcs1pad(rsa,sha256)
        driver       : pkcs1pad(rsa-generic,sha256)
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : akcipher

        name         : ecdh-nist-p256
        driver       : ecdh-generic
        module       : ecdh_generic
        priority     : 100
        refcnt       : 2
        selftest     : passed
        internal     : no
        type         : kpp

        name         : ecdh-nist-p192
        driver       : ecdh-generic
        module       : ecdh_generic
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : kpp

        name         : sha3-512
        driver       : sha3-512-generic
        module       : sha3_generic
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 72
        digestsize   : 64

        name         : sha3-384
        driver       : sha3-384-generic
        module       : sha3_generic
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 104
        digestsize   : 48

        name         : sha3-256
        driver       : sha3-256-generic
        module       : sha3_generic
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 136
        digestsize   : 32

        name         : sha3-224
        driver       : sha3-224-generic
        module       : sha3_generic
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 144
        digestsize   : 28

        name         : sha512
        driver       : sha512-ce
        module       : sha512_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 128
        digestsize   : 64

        name         : sha384
        driver       : sha384-ce
        module       : sha512_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 128
        digestsize   : 48

        name         : sha384
        driver       : sha384-arm64
        module       : sha512_arm64
        priority     : 150
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 128
        digestsize   : 48

        name         : sha512
        driver       : sha512-arm64
        module       : sha512_arm64
        priority     : 150
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 128
        digestsize   : 64

        name         : sha256
        driver       : sha256-ce
        module       : sha2_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 32

        name         : sha224
        driver       : sha224-ce
        module       : sha2_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 28

        name         : sha224
        driver       : sha224-arm64-neon
        module       : sha256_arm64
        priority     : 150
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 28

        name         : sha256
        driver       : sha256-arm64-neon
        module       : sha256_arm64
        priority     : 150
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 32

        name         : sha224
        driver       : sha224-arm64
        module       : sha256_arm64
        priority     : 125
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 28

        name         : sha256
        driver       : sha256-arm64
        module       : sha256_arm64
        priority     : 125
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 32

        name         : sha1
        driver       : sha1-ce
        module       : sha1_ce
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 20

        name         : pkcs1pad(rsa,sha512)
        driver       : pkcs1pad(rsa-generic,sha512)
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : akcipher

        name         : jitterentropy_rng
        driver       : jitterentropy_rng
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : ghash
        driver       : ghash-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 16
        digestsize   : 16

        name         : stdrng
        driver       : drbg_nopr_hmac_sha256
        module       : kernel
        priority     : 221
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_hmac_sha512
        module       : kernel
        priority     : 220
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_hmac_sha384
        module       : kernel
        priority     : 219
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_hmac_sha1
        module       : kernel
        priority     : 218
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_sha256
        module       : kernel
        priority     : 217
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_sha512
        module       : kernel
        priority     : 216
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_sha384
        module       : kernel
        priority     : 215
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_sha1
        module       : kernel
        priority     : 214
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_ctr_aes256
        module       : kernel
        priority     : 213
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_ctr_aes192
        module       : kernel
        priority     : 212
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_nopr_ctr_aes128
        module       : kernel
        priority     : 211
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_hmac_sha256
        module       : kernel
        priority     : 210
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_hmac_sha512
        module       : kernel
        priority     : 209
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_hmac_sha384
        module       : kernel
        priority     : 208
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_hmac_sha1
        module       : kernel
        priority     : 207
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_sha256
        module       : kernel
        priority     : 206
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_sha512
        module       : kernel
        priority     : 205
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_sha384
        module       : kernel
        priority     : 204
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_sha1
        module       : kernel
        priority     : 203
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_ctr_aes256
        module       : kernel
        priority     : 202
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_ctr_aes192
        module       : kernel
        priority     : 201
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : stdrng
        driver       : drbg_pr_ctr_aes128
        module       : kernel
        priority     : 200
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : rng
        seedsize     : 0

        name         : lzo-rle
        driver       : lzo-rle-scomp
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : scomp

        name         : lzo-rle
        driver       : lzo-rle-generic
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : compression

        name         : lzo
        driver       : lzo-scomp
        module       : kernel
        priority     : 0
        refcnt       : 9
        selftest     : passed
        internal     : no
        type         : scomp

        name         : lzo
        driver       : lzo-generic
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : compression

        name         : crct10dif
        driver       : crct10dif-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 1
        digestsize   : 2

        name         : crc32c
        driver       : crc32c-generic
        module       : kernel
        priority     : 100
        refcnt       : 3
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 1
        digestsize   : 4

        name         : zlib-deflate
        driver       : zlib-deflate-scomp
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : scomp

        name         : deflate
        driver       : deflate-scomp
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : scomp

        name         : deflate
        driver       : deflate-generic
        module       : kernel
        priority     : 0
        refcnt       : 2
        selftest     : passed
        internal     : no
        type         : compression

        name         : aes
        driver       : aes-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : cipher
        blocksize    : 16
        min keysize  : 16
        max keysize  : 32

        name         : sha384
        driver       : sha384-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 128
        digestsize   : 48

        name         : sha512
        driver       : sha512-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 128
        digestsize   : 64

        name         : sha224
        driver       : sha224-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 28

        name         : sha256
        driver       : sha256-generic
        module       : kernel
        priority     : 100
        refcnt       : 6
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 32

        name         : sha1
        driver       : sha1-generic
        module       : kernel
        priority     : 100
        refcnt       : 8
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 20

        name         : md5
        driver       : md5-generic
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 64
        digestsize   : 16

        name         : ecb(cipher_null)
        driver       : ecb-cipher_null
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : skcipher
        async        : no
        blocksize    : 1
        min keysize  : 0
        max keysize  : 0
        ivsize       : 0
        chunksize    : 1
        walksize     : 1

        name         : digest_null
        driver       : digest_null-generic
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : shash
        blocksize    : 1
        digestsize   : 0

        name         : compress_null
        driver       : compress_null-generic
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : compression

        name         : cipher_null
        driver       : cipher_null-generic
        module       : kernel
        priority     : 0
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : cipher
        blocksize    : 1
        min keysize  : 0
        max keysize  : 0

        name         : rsa
        driver       : rsa-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : akcipher

        name         : dh
        driver       : dh-generic
        module       : kernel
        priority     : 100
        refcnt       : 1
        selftest     : passed
        internal     : no
        type         : kpp
    """
    }
}

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

class DigitalSignatureAlgorithm (length: Int) {
    private var p:BigInteger
    private var q:BigInteger
    private var h:BigInteger
    private var g:BigInteger

    init {
        val (pTemp, qTemp) = generatePQ(length)
        val (hTemp, gTemp) = generateHG(pTemp, qTemp)
        p = pTemp
        q = qTemp
        h = hTemp
        g = gTemp
    }

    fun sign(x:BigInteger, m:ByteArray, md:MessageDigest):Pair<BigInteger, BigInteger> {
        do {
            val j = getRandomBigInteger(BigInteger.TWO, q- BigInteger.ONE)
            val r = squareMultiply(g,j,p) % q
            if (r== BigInteger.ZERO) continue // choose new j

            val jInv = eeA(j,q)[1]+q
            val s = jInv * (md.digest(m).asPositiveBigInteger() + r*x) % q

            if (s != BigInteger.ZERO) return Pair(r,s)
            // else choose new j and try again
        } while (true)
    }

    fun verify(y:BigInteger, m:ByteArray, md:MessageDigest, r:BigInteger, s:BigInteger):Boolean {
        if (!(BigInteger.ZERO<r && r<q && BigInteger.ZERO<s && s<q)) return false

        val w = eeA(s,q)[1]+q // to prevent negative values
        val u1 = md.digest(m).asPositiveBigInteger()*w % q
        val u2 = r*w % q
        val v = squareMultiply(g,u1,p) * squareMultiply(y,u2,p) % q

        return v == r
    }


    private fun generatePQ(lengthOfQ: Int):Pair<BigInteger, BigInteger> {
        do {
            val q = getPrime(lengthOfQ)

            for (k in 1..100) { // the upper limit should be adjusted according to the desired length of q
                val p = BigInteger.valueOf(k.toLong())*q + BigInteger.ONE
                if (isProbablePrime(p)) {
                    return Pair(p,q)
                }
            }

        } while (true)
    }

    private fun generateHG(p:BigInteger, q:BigInteger):Pair<BigInteger, BigInteger> {
        var h:BigInteger
        var g:BigInteger
        do {
            h = getRandomBigInteger(BigInteger.TWO, p- BigInteger.TWO)
            g = squareMultiply(h, (p- BigInteger.ONE)/q, p)
        } while (g == BigInteger.ONE)
        return Pair(h,g)
    }


    private fun getPrime(length:Int): BigInteger {
        val random = SecureRandom()
        val z = BigInteger(length,random)
        val init = z * BigInteger.valueOf(30)
        var n: BigInteger
        for (j in 0..200) {
            for (i in getSomePrimes()) {
                n = init + BigInteger.valueOf(i.toLong())+ BigInteger.valueOf(j.toLong())* BigInteger.valueOf(30)
                if (isProbablePrime(n)) {
                    return n
                }
            }
        }
        throw IllegalArgumentException()
    }

    private fun isProbablePrime(num: BigInteger):Boolean {
        for (i in 1..20) {
            if (!testMillerRabin(num)) {
                return false
            }
        }
        return true
    }

    private fun getSomePrimes():IntArray {
        return intArrayOf(1, 7, 11, 13, 17, 19, 23, 29)
    }

    private fun testMillerRabin(n: BigInteger): Boolean {
        var m: BigInteger
        var k = 0
        do {
            k++
            m = (n- BigInteger.ONE)/ BigInteger.valueOf(2).pow(k)
        } while (m % BigInteger.valueOf(2) == BigInteger.ZERO)
        val a = getRandomBigInteger(BigInteger.valueOf(2), n - BigInteger.ONE)
        var b = squareMultiply(a, m, n)
        if (b % n == BigInteger.ONE) {
            return true
        }
        for (i in 1..k) {
            if (b % n == n- BigInteger.ONE || b % n ==-BigInteger.ONE) {
                return true
            } else {
                b = squareMultiply(b, BigInteger.valueOf(2), n)
            }
        }
        return false
    }

    private fun getRandomBigInteger(min: BigInteger, max: BigInteger): BigInteger {
        val random = SecureRandom()
        var result: BigInteger
        do {
            result = BigInteger(max.bitLength(), random)
        } while (result < min || result > max)

        return result
    }

    private fun squareMultiply(xNum: BigInteger, exponent: BigInteger, modulus: BigInteger): BigInteger {
        // BigInteger.modPow() would probably do the trick too (though I don't know how exactly it is implemented),
        // but since it is part of the exercise this is the implementation "from scratch"
        var x = xNum
        var y = BigInteger.ONE
        val r = exponent.bitLength()
        for (i in 0..r) {
            if (exponent.testBit(i)) {
                y = y*x % modulus
            }
            x = x.pow(2) % modulus
        }

        return y
    }

    private fun eeA(a:BigInteger, b:BigInteger):Array<BigInteger> {
        // this could also be done by using the built-in BigInteger.modInverse() function
        var r0 = a; var r1 = b
        var (k,s0,s1,t0,t1) = listOf( BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE )

        do {
            k++
            val qk = r0 / (r1)
            val rkTmp = r1
            r1 = r0 - qk*rkTmp
            val skTmp = s1
            s1 = s0 - qk*skTmp
            val tkTmp = t1
            t1 = t0 - qk*tkTmp

            r0 = rkTmp
            s0 = skTmp
            t0 = tkTmp

        } while (r1 != BigInteger.ZERO)

        return arrayOf(r0,s0,t0)
    }

    private fun ByteArray.asPositiveBigInteger():BigInteger {
        return BigInteger(byteArrayOf(0)+this)
        //the 0-Byte prefix prevents the byteArray to be interpreted as negative when the 1st bit in the byteArray is set
    }

}
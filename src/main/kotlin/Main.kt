import java.security.MessageDigest

fun main() {
    val dsa = DigitalSignatureAlgorithm(1024,160)
    val (x, y) = dsa.generateXY(dsa.q)
    println("g= ${dsa.g}")
    println("p= ${dsa.p}")
    println("q= ${dsa.q}")
    println("x= $x")
    println("y= $y")

    val message = "Hi"
    val md = MessageDigest.getInstance("SHA-1")

    val (r,s) = dsa.sign(x, message.toByteArray(), md)

    println("r= $r")
    println("s= $s")

    println(dsa.verify(y, message.toByteArray(), md, r, s))
}
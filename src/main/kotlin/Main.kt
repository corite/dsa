import java.security.MessageDigest

fun main() {
    val dsa = DigitalSignatureAlgorithm(1024,160)
    val (x, y) = dsa.generateXY(dsa.q)
    println("g= ${dsa.g}")
    println("p= ${dsa.p}")
    println("q= ${dsa.q}")
    println("x= $x")
    println("y= $y")


    val message = "Hello World!"
    val md = MessageDigest.getInstance("SHA-1")
    println("message= $message")
    println("message in bytes= ${message.toByteArray().joinToString (" "){ it.toString(16) }}")


    val (r, s) = dsa.sign(x, message.toByteArray(), md)

    println("r= $r")
    println("s= $s")

    println("isValid= ${dsa.verify(y, message.toByteArray(), md, r, s)}")
}
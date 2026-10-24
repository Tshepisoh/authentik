package app.authentik.protection.dns

/*
 * Just enough IPv4, UDP and DNS to answer lookups that arrive on the VPN's
 * tun interface. No Android imports, so it runs in plain JVM tests. Anything
 * unexpected parses to null and is dropped; nothing here may throw on hostile
 * input.
 */

/** A UDP datagram addressed to port 53, as read from the tun interface. */
class Datagram(
  val src: ByteArray,
  val dst: ByteArray,
  val srcPort: Int,
  val dstPort: Int,
  val payload: ByteArray,
)

object Ipv4Udp {
  private const val UDP = 17

  fun parse(buf: ByteArray, length: Int): Datagram? {
    if (length < 28 || length > buf.size) return null
    if (buf[0].toInt() ushr 4 != 4) return null
    val ihl = (buf[0].toInt() and 0x0F) * 4
    val total = u16(buf, 2)
    if (ihl < 20 || total > length || total < ihl + 8) return null
    if (buf[9].toInt() and 0xFF != UDP) return null
    // Fragments: DNS queries are never fragmented in practice; drop rather than reassemble.
    val frag = u16(buf, 6)
    if (frag and 0x2000 != 0 || frag and 0x1FFF != 0) return null

    val udpLen = u16(buf, ihl + 4)
    if (udpLen < 8 || ihl + udpLen > total) return null
    val dstPort = u16(buf, ihl + 2)
    if (dstPort != 53) return null
    return Datagram(
      src = buf.copyOfRange(12, 16),
      dst = buf.copyOfRange(16, 20),
      srcPort = u16(buf, ihl),
      dstPort = dstPort,
      payload = buf.copyOfRange(ihl + 8, ihl + udpLen),
    )
  }

  /** An IPv4/UDP packet with valid IP and UDP checksums. */
  fun build(src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
    val udpLen = 8 + payload.size
    val total = 20 + udpLen
    val p = ByteArray(total)
    p[0] = 0x45
    put16(p, 2, total)
    put16(p, 6, 0x4000) // don't fragment
    p[8] = 64 // TTL
    p[9] = UDP.toByte()
    src.copyInto(p, 12)
    dst.copyInto(p, 16)
    put16(p, 10, checksum(p, 0, 20, 0))

    put16(p, 20, srcPort)
    put16(p, 22, dstPort)
    put16(p, 24, udpLen)
    payload.copyInto(p, 28)
    // Pseudo-header: source, destination, protocol, UDP length.
    val pseudo = sum(p, 12, 8) + UDP + udpLen
    val c = checksum(p, 20, udpLen, pseudo)
    put16(p, 26, if (c == 0) 0xFFFF else c)
    return p
  }

  fun u16(b: ByteArray, at: Int) = ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

  private fun put16(b: ByteArray, at: Int, v: Int) {
    b[at] = (v ushr 8).toByte()
    b[at + 1] = v.toByte()
  }

  private fun sum(b: ByteArray, from: Int, len: Int): Int {
    var s = 0
    var i = from
    while (i + 1 < from + len) {
      s += u16(b, i)
      i += 2
    }
    if (i < from + len) s += (b[i].toInt() and 0xFF) shl 8
    return s
  }

  /** Ones'-complement checksum over [from, from+len), plus `initial`. */
  fun checksum(b: ByteArray, from: Int, len: Int, initial: Int): Int {
    var s = initial + sum(b, from, len)
    while (s ushr 16 != 0) s = (s and 0xFFFF) + (s ushr 16)
    return s.inv() and 0xFFFF
  }
}

/** The one question in a standard DNS query. */
data class Question(val name: String, val type: Int, val endOffset: Int)

object Dns {
  const val NOERROR = 0
  const val SERVFAIL = 2
  const val NXDOMAIN = 3

  /** The question of a standard query (QR=0, opcode 0, exactly one question), or null. */
  fun question(msg: ByteArray): Question? {
    if (msg.size < 12) return null
    val flags = Ipv4Udp.u16(msg, 2)
    if (flags and 0x8000 != 0) return null // a response, not a query
    if ((flags ushr 11) and 0x0F != 0) return null // not a standard query
    if (Ipv4Udp.u16(msg, 4) != 1) return null

    val labels = mutableListOf<String>()
    var i = 12
    var nameLen = 0
    while (true) {
      if (i >= msg.size) return null
      val len = msg[i].toInt() and 0xFF
      if (len == 0) {
        i++
        break
      }
      // Compression pointers have no business in a question; refuse rather than chase them.
      if (len and 0xC0 != 0) return null
      if (i + 1 + len > msg.size) return null
      nameLen += len + 1
      if (nameLen > 255) return null
      labels += String(msg, i + 1, len, Charsets.ISO_8859_1).lowercase()
      i += 1 + len
    }
    if (i + 4 > msg.size) return null
    return Question(labels.joinToString("."), Ipv4Udp.u16(msg, i), i + 4)
  }

  /** A response with no answers and the given code, echoing the query's id, RD bit and question. */
  fun reply(query: ByteArray, q: Question, rcode: Int): ByteArray {
    val out = query.copyOfRange(0, q.endOffset)
    val rd = Ipv4Udp.u16(query, 2) and 0x0100
    val flags = 0x8000 or rd or 0x0080 or (rcode and 0x0F) // QR, RD (copied), RA, RCODE
    out[2] = (flags ushr 8).toByte()
    out[3] = flags.toByte()
    // QDCOUNT stays 1; ANCOUNT, NSCOUNT and ARCOUNT are zero (drops any EDNS record from the query).
    for (k in 6 until 12) out[k] = 0
    return out
  }
}

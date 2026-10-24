package app.authentik.protection.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import kotlin.random.Random

class PacketsTest {
  private val phone = byteArrayOf(10, 111, 222.toByte(), 1)
  private val dns = byteArrayOf(10, 111, 222.toByte(), 2)

  /** A standard query for `name`, type A, with RD set and an EDNS OPT record. */
  private fun query(name: String, id: Int = 0x1234, withOpt: Boolean = true): ByteArray {
    val q = mutableListOf<Byte>()
    q += listOf(id ushr 8, id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, if (withOpt) 1 else 0).map { it.toByte() }
    for (label in name.split('.')) {
      q += label.length.toByte()
      q += label.toByteArray().toList()
    }
    q += listOf(0, 0, 1, 0, 1).map { it.toByte() }
    if (withOpt) q += listOf(0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0).map { it.toByte() }
    return q.toByteArray()
  }

  private fun packet(payload: ByteArray, dstPort: Int = 53) = Ipv4Udp.build(phone, dns, 40000, dstPort, payload)

  @Test
  fun `parses a UDP query to port 53`() {
    val d = Ipv4Udp.parse(packet(query("example.com")).let { it + ByteArray(10) }, 28 + query("example.com").size)!!
    assertArrayEquals(phone, d.src)
    assertArrayEquals(dns, d.dst)
    assertEquals(40000, d.srcPort)
    assertEquals(Question("example.com", 1, 12 + 13 + 4), Dns.question(d.payload))
  }

  @Test
  fun `built packets carry valid checksums`() {
    val p = packet(query("fnb.co.za"))
    // Re-summing a header that includes its checksum gives zero.
    assertEquals(0, Ipv4Udp.checksum(p, 0, 20, 0))
    val pseudo = (Ipv4Udp.u16(p, 12) + Ipv4Udp.u16(p, 14) + Ipv4Udp.u16(p, 16) + Ipv4Udp.u16(p, 18)) + 17 + (p.size - 20)
    assertEquals(0, Ipv4Udp.checksum(p, 20, p.size - 20, pseudo))
  }

  @Test
  fun `ignores other ports, TCP, IPv6, fragments and short packets`() {
    assertNull(Ipv4Udp.parse(packet(query("a.com"), dstPort = 853), 100))
    val tcp = packet(query("a.com")).also { it[9] = 6 }
    assertNull(Ipv4Udp.parse(tcp, tcp.size))
    val v6 = packet(query("a.com")).also { it[0] = 0x60 }
    assertNull(Ipv4Udp.parse(v6, v6.size))
    val frag = packet(query("a.com")).also { it[6] = 0x20 }
    assertNull(Ipv4Udp.parse(frag, frag.size))
    assertNull(Ipv4Udp.parse(ByteArray(10), 10))
  }

  @Test
  fun `NXDOMAIN reply echoes id, RD and question, and drops extra records`() {
    val qBytes = query("pay-release.top", id = 0xBEEF)
    val q = Dns.question(qBytes)!!
    val r = Dns.reply(qBytes, q, Dns.NXDOMAIN)
    assertEquals(0xBEEF, Ipv4Udp.u16(r, 0))
    val flags = Ipv4Udp.u16(r, 2)
    assertEquals(0x8000, flags and 0x8000) // response
    assertEquals(0x0100, flags and 0x0100) // RD copied
    assertEquals(Dns.NXDOMAIN, flags and 0x0F)
    assertEquals(1, Ipv4Udp.u16(r, 4))
    assertEquals(0, Ipv4Udp.u16(r, 10)) // no OPT record
    assertEquals(q.endOffset, r.size)
    assertEquals("pay-release.top", Dns.question(r.copyOf().also { it[2] = 0x01; it[3] = 0 })!!.name)
  }

  @Test
  fun `refuses responses, odd opcodes, compression and overlong names`() {
    val resp = query("a.com").also { it[2] = 0x81.toByte() }
    assertNull(Dns.question(resp))
    val update = query("a.com").also { it[2] = 0x28 }
    assertNull(Dns.question(update))
    val pointer = query("a.com").also { it[12] = 0xC0.toByte() }
    assertNull(Dns.question(pointer))
    val long = (1..9).joinToString(".") { "a".repeat(30) }
    assertNull(Dns.question(query(long)))
  }

  @Test
  fun `never throws on random bytes`() {
    val rnd = Random(42)
    repeat(20_000) {
      val b = rnd.nextBytes(rnd.nextInt(0, 120))
      Ipv4Udp.parse(b, b.size)?.let { Dns.question(it.payload) }
      Dns.question(b)
    }
    // And a mangled real packet still parses or is refused cleanly.
    val p = packet(query("example.com"))
    repeat(5_000) {
      val m = p.copyOf().also { it[rnd.nextInt(it.size)] = rnd.nextInt().toByte() }
      Ipv4Udp.parse(m, m.size)?.let { Dns.question(it.payload) }
    }
    assertNotNull(Ipv4Udp.parse(p, p.size))
  }
}

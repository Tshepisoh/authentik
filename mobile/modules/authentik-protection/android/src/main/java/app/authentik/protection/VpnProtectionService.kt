package app.authentik.protection

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import app.authentik.protection.dns.Datagram
import app.authentik.protection.dns.Dns
import app.authentik.protection.dns.DnsDecision
import app.authentik.protection.dns.DnsPolicy
import app.authentik.protection.dns.Ipv4Udp
import app.authentik.protection.dns.Question
import app.authentik.protection.rules.ThreatIntel
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * A local, DNS-only VPN. Only packets addressed to the VPN's own DNS server
 * enter the tunnel; every other connection goes straight to the real network,
 * so there's nothing to decrypt and little to wake up for. Lookups for domains
 * on the threat list get NXDOMAIN; look-alike domains are answered normally and
 * raise a warning. Ordinary lookups are forwarded to the network's own DNS
 * servers (or 1.1.1.1 / 8.8.8.8 if none answer) and never recorded.
 *
 * What it can't see: Private DNS in strict mode, apps that use their own
 * DNS-over-HTTPS, cached answers and direct-IP connections.
 */
class VpnProtectionService : VpnService() {
  private lateinit var store: VpnStore
  private var tun: ParcelFileDescriptor? = null
  private var reader: Thread? = null
  private var pool: ThreadPoolExecutor? = null
  private var callback: ConnectivityManager.NetworkCallback? = null

  @Volatile private var active = false
  @Volatile private var network: Network? = null
  @Volatile private var upstream: List<InetAddress> = emptyList()

  // Tried first, so one dead server doesn't slow every lookup. Reset when the network changes.
  @Volatile private var preferred: InetAddress? = null

  // Last time each host raised a notification, so one site doesn't flood the shade.
  private val lastNotified = ConcurrentHashMap<String, Long>()

  override fun onCreate() {
    super.onCreate()
    store = VpnStore(this)
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_STOP -> {
        store.enabled = false
        VpnState.lastError = null
        shutdown(null)
        return START_NOT_STICKY
      }
      // SERVICE_INTERFACE: started by Android for always-on VPN.
      ACTION_START, SERVICE_INTERFACE -> store.enabled = true
      // Null intent: restarted after the process was killed (START_STICKY).
      null -> if (!store.enabled) {
        stopSelf()
        return START_NOT_STICKY
      }
    }
    if (tun == null) startTunnel()
    return START_STICKY
  }

  override fun onRevoke() {
    store.enabled = false
    shutdown("Another VPN was turned on, or the VPN was turned off in Android settings.")
  }

  override fun onDestroy() {
    shutdown(null)
    super.onDestroy()
  }

  private fun startTunnel() {
    // Must happen promptly after startForegroundService().
    ServiceCompat.startForeground(
      this,
      NOTIFICATION_ID,
      statusNotification(),
      if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED else 0,
    )
    if (prepare(this) != null) {
      store.enabled = false
      return shutdown("Authentik doesn't have permission to run the VPN. Turn web protection on again in the app.")
    }
    watchNetwork()

    val builder = Builder()
      .setSession("Authentik web protection")
      .addAddress(TUN_ADDRESS, 32)
      .addDnsServer(DNS_ADDRESS)
      .addRoute(DNS_ADDRESS, 32)
      .setBlocking(true)
      .setMtu(1500)
      .setConfigureIntent(openApp())
    // Follow the real network's metered state instead of always looking metered.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
    network?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
    // Authentik's own traffic, including its upstream lookups and API calls, stays off the tunnel.
    try {
      builder.addDisallowedApplication(packageName)
    } catch (_: PackageManager.NameNotFoundException) {
    }

    val fd = try {
      builder.establish()
    } catch (_: Exception) {
      null
    }
    if (fd == null) {
      store.enabled = false
      return shutdown("Android didn't start the VPN. Another VPN app may be set to always-on.")
    }

    tun = fd
    active = true
    VpnState.reset(running = true)
    // A page needs dozens of lookups at once. Core == max, because a ThreadPoolExecutor only grows
    // past its core size when the queue is full, which left two threads serving every lookup.
    pool = ThreadPoolExecutor(LOOKUP_THREADS, LOOKUP_THREADS, 30, TimeUnit.SECONDS, ArrayBlockingQueue(256), ThreadPoolExecutor.DiscardOldestPolicy())
      .apply { allowCoreThreadTimeOut(true) }
    reader = Thread({ readLoop(fd) }, "authentik-dns").also { it.start() }
    VpnState.changed()
  }

  /** Reads queries until stopped. Polls with a timeout so it notices `active = false` without relying on close(). */
  private fun readLoop(fd: ParcelFileDescriptor) {
    val input = FileInputStream(fd.fileDescriptor)
    val output = FileOutputStream(fd.fileDescriptor)
    val buf = ByteArray(32_767)
    val poll = StructPollfd().apply {
      this.fd = fd.fileDescriptor
      events = OsConstants.POLLIN.toShort()
    }
    try {
      while (active) {
        val ready = try {
          Os.poll(arrayOf(poll), 1000)
        } catch (e: ErrnoException) {
          if (e.errno == OsConstants.EINTR) continue else break
        }
        if (ready == 0) continue
        if (poll.revents.toInt() and (OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL) != 0) break
        val n = try {
          input.read(buf)
        } catch (_: IOException) {
          break
        }
        if (n <= 0) continue
        // Anything that isn't a UDP query to our DNS address (DNS over TCP, DoT on 853) is dropped;
        // resolvers then fall back to plain UDP.
        val datagram = Ipv4Udp.parse(buf, n) ?: continue
        val question = Dns.question(datagram.payload)
        VpnState.lookups.incrementAndGet()
        pool?.execute { handle(datagram, question, output) }
      }
    } finally {
      try {
        fd.close()
      } catch (_: IOException) {
      }
    }
  }

  private fun handle(d: Datagram, q: Question?, output: FileOutputStream) {
    val decision = if (q == null) DnsDecision.Allow else DnsPolicy.decide(q.name, ThreatListStore.get(this).intel())
    when (decision) {
      is DnsDecision.Block -> {
        VpnState.blocked.incrementAndGet()
        write(output, Ipv4Udp.build(d.dst, d.src, d.dstPort, d.srcPort, Dns.reply(d.payload, q!!, Dns.NXDOMAIN)))
        record(DnsEvent(q.name, System.currentTimeMillis(), "blocked", ThreatIntel.label(decision.threatType)), BLOCK_NOTIFY_MS)
      }
      is DnsDecision.Warn -> {
        VpnState.warned.incrementAndGet()
        forward(d, q, output)
        record(DnsEvent(q!!.name, System.currentTimeMillis(), "lookalike", decision.brand), WARN_NOTIFY_MS)
      }
      DnsDecision.Allow -> forward(d, q, output)
    }
  }

  /** Sends the query upstream and relays the first valid answer. SERVFAIL if none answer. */
  private fun forward(d: Datagram, q: Question?, output: FileOutputStream) {
    val id = Ipv4Udp.u16(d.payload, 0)
    for (server in candidates()) {
      val resp = try {
        query(server, d.payload)
      } catch (_: Exception) {
        null // Unreachable, timed out, or the network went away: try the next server.
      }
      if (resp == null || resp.size < 12 || Ipv4Udp.u16(resp, 0) != id) continue
      preferred = server
      write(output, Ipv4Udp.build(d.dst, d.src, d.dstPort, d.srcPort, resp))
      return
    }
    if (q != null) write(output, Ipv4Udp.build(d.dst, d.src, d.dstPort, d.srcPort, Dns.reply(d.payload, q, Dns.SERVFAIL)))
  }

  /**
   * The server that answered last, then the network's own (IPv4 first: an IPv6 server the
   * network can't reach would otherwise stall every lookup), then the public fallbacks.
   */
  private fun candidates(): List<InetAddress> {
    val own = upstream.sortedBy { if (it is Inet4Address) 0 else 1 }
    return (listOfNotNull(preferred) + own + FALLBACK_DNS).distinct().take(MAX_ATTEMPTS)
  }

  private fun query(server: InetAddress, payload: ByteArray): ByteArray =
    DatagramSocket().use { s ->
      protect(s)
      // Authentik is outside its own VPN, so an unbound socket still uses the real network.
      try {
        network?.bindSocket(s)
      } catch (_: Exception) {
      }
      s.soTimeout = UPSTREAM_TIMEOUT_MS
      s.send(DatagramPacket(payload, payload.size, InetSocketAddress(server, 53)))
      val buf = ByteArray(4096)
      val packet = DatagramPacket(buf, buf.size)
      s.receive(packet)
      buf.copyOf(packet.length)
    }

  private fun write(output: FileOutputStream, packet: ByteArray) {
    try {
      synchronized(output) { output.write(packet) }
    } catch (_: IOException) {
      // The tunnel closed while answering.
    }
  }

  private fun record(event: DnsEvent, throttleMs: Long) {
    val key = "${event.kind}:${event.host}"
    val last = lastNotified[key]
    if (last != null && event.at - last < throttleMs) return
    lastNotified[key] = event.at
    store.add(event)
    WarningNotifier.postDns(this, event)
    VpnState.changed()
  }

  /**
   * Follows the real default network. Authentik is excluded from its own VPN,
   * so its default network is the underlying one, not the tunnel.
   */
  private fun watchNetwork() {
    val cm = getSystemService(ConnectivityManager::class.java)
    cm.activeNetwork?.let { n ->
      network = n
      cm.getLinkProperties(n)?.let(::applyLinkProperties)
    }
    val cb = object : ConnectivityManager.NetworkCallback() {
      override fun onAvailable(n: Network) {
        network = n
        setUnderlyingNetworks(arrayOf(n))
      }

      override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) {
        if (n == network) applyLinkProperties(lp)
      }

      override fun onLost(n: Network) {
        if (n != network) return
        network = null
        upstream = emptyList()
        preferred = null
        VpnState.upstreamServers = 0
        setUnderlyingNetworks(null)
        VpnState.changed()
      }
    }
    cm.registerDefaultNetworkCallback(cb)
    callback = cb
  }

  private fun applyLinkProperties(lp: LinkProperties) {
    if (lp.dnsServers != upstream) preferred = null
    upstream = lp.dnsServers
    VpnState.upstreamServers = lp.dnsServers.size
    // Strict Private DNS sends lookups straight to that provider over TLS, past this VPN.
    VpnState.privateDnsHost = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) lp.privateDnsServerName else null
    VpnState.changed()
  }

  private fun shutdown(reason: String?) {
    active = false
    if (reason != null) VpnState.lastError = reason
    VpnState.running = false
    callback?.let {
      try {
        getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it)
      } catch (_: IllegalArgumentException) {
      }
    }
    callback = null
    // The reader closes the tunnel within a second; close it here if it never started.
    if (reader == null) {
      try {
        tun?.close()
      } catch (_: IOException) {
      }
    }
    tun = null
    reader = null
    pool?.shutdownNow()
    pool = null
    ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    stopSelf()
    VpnState.changed()
  }

  private fun openApp(): PendingIntent = PendingIntent.getActivity(
    this,
    1,
    Intent(Intent.ACTION_VIEW, Uri.parse(DEEP_LINK)).setPackage(packageName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
  )

  private fun statusNotification(): android.app.Notification {
    NotificationManagerCompat.from(this).createNotificationChannel(
      NotificationChannelCompat.Builder(STATUS_CHANNEL, NotificationManagerCompat.IMPORTANCE_LOW)
        .setName("Web protection status")
        .setDescription("Shown while Authentik's web protection is on")
        .build(),
    )
    val stop = PendingIntent.getService(
      this,
      2,
      Intent(this, VpnProtectionService::class.java).setAction(ACTION_STOP),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    return NotificationCompat.Builder(this, STATUS_CHANNEL)
      .setSmallIcon(R.drawable.authentik_protection_shield)
      .setContentTitle("Web protection is on")
      .setContentText("Blocking known scam sites. Website lookups aren't recorded.")
      .setOngoing(true)
      .setContentIntent(openApp())
      .addAction(0, "Turn off", stop)
      .build()
  }

  companion object {
    const val ACTION_START = "app.authentik.protection.vpn.START"
    const val ACTION_STOP = "app.authentik.protection.vpn.STOP"

    // Private addresses only ever used inside the tunnel.
    private const val TUN_ADDRESS = "10.111.222.1"
    private const val DNS_ADDRESS = "10.111.222.2"
    private const val NOTIFICATION_ID = 0x4155
    private const val STATUS_CHANNEL = "web-protection-status"
    private const val DEEP_LINK = "authentik://web-protection"
    private const val BLOCK_NOTIFY_MS = 10 * 60 * 1000L
    private const val WARN_NOTIFY_MS = 24 * 60 * 60 * 1000L

    // Used only when the network has no DNS servers of its own, or none of them answer.
    private val FALLBACK_DNS: List<InetAddress> = listOf("1.1.1.1", "8.8.8.8").map { InetAddress.getByName(it) }
    private const val LOOKUP_THREADS = 16
    private const val UPSTREAM_TIMEOUT_MS = 2000
    private const val MAX_ATTEMPTS = 4

    fun start(context: Context) {
      ContextCompat.startForegroundService(context, Intent(context, VpnProtectionService::class.java).setAction(ACTION_START))
    }

    fun stop(context: Context) {
      context.startService(Intent(context, VpnProtectionService::class.java).setAction(ACTION_STOP))
    }
  }
}

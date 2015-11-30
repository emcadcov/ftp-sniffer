import java.util.Date

import org.jnetpcap.Pcap._
import org.jnetpcap.PcapBpfProgram
import org.jnetpcap.nio.JNumber
import org.jnetpcap.packet.{Payload, PcapPacket, PcapPacketHandler, format}
import org.jnetpcap.protocol.network.Ip4

object Sniffer {

  val MaxBytesToCapture = 2048
  val ReceiptAllPackets = 1
  val PacketWaitingTimeMs = 512
  val PacketsLoopCount = -1
  val User = "xuserx"
  val StringFilter = "port ftp or ftp-data"
  val Optimize = 1

  def main(args: Array[String]) {

    val errBuf: java.lang.StringBuilder = new java.lang.StringBuilder

    // получение имени устройства
    val device = lookupDev(errBuf)
    println(s"Open device $device...")

    // создание дескриптора для захвата пакетов по сети
    val descriptor = openLive(
      device, MaxBytesToCapture, ReceiptAllPackets, PacketWaitingTimeMs, errBuf
    ) match {
      case null =>
        println(errBuf)
        return
      case o    => o
    }

    val netAddress = new JNumber()
    val mask = new JNumber()
    // получение сетевого адреса (ipv4) и маски сети
    lookupNet(device, netAddress, mask, errBuf)

    val filter = new PcapBpfProgram()
    // заполнение filter нужной информацией
    if (descriptor.compile(filter, StringFilter, Optimize, mask.intValue) == -1) {
      println("Error in compile filter")
      return
    }
    // установка фильтра
    if (descriptor.setFilter(filter) == -1) {
      println("Error in setting filter")
      return
    }
    // обрабатывать все пакеты функцией getPacketHandler
    descriptor.loop(PacketsLoopCount, getPacketHandler, User)
    descriptor.close()

  }
  // создаёт обработчик для пакетов и переопределяет его метод nextPacket
  def getPacketHandler = new PcapPacketHandler[String] {

    override def nextPacket(packet: PcapPacket, user: String): Unit = {
      // пакеты, которые почему-то прошли фильтр, но не содержат payload, отсеиваются
      val data: String = findContent(packet) match {
	      case Some(d)  => d
	      case None     => return
      }

      println(new Date(packet.getCaptureHeader.timestampInMillis()) + "\n")
      println(findLength(packet) + "\n")
      println(findIp(packet) + "\n")
      println(data)
      println("-----------------------------")

    }

    // получение адресов пакетов только для ipv4
    def findIp(packet: PcapPacket): String = {
      val ip = new Ip4
      if (packet.hasHeader(ip)) {
        "Destination IP: " + format.FormatUtils.ip(ip.destination) +
          "\nSource IP: " + format.FormatUtils.ip(ip.source)
      } else {
        "Unknown IP"
      }
    }

    // получение содержимого пакета
    def findContent(packet: PcapPacket): Option[String] = {

      val payload = new Payload
      if (packet.hasHeader(payload)) {
	      Some("Info:\n" + new String(payload.getByteArray(0, payload.getLength).map(_.toChar)))
      } else {
	      None
      }
    }

    def findLength(packet: PcapPacket): String = {
      "Length: " + packet.getCaptureHeader.caplen().toString
    }
  }

}

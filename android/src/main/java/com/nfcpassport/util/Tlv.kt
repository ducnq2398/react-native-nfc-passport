package com.nfcpassport.util

/**
 * BER-TLV tối giản (ISO/IEC 7816-4 Annex D) — đủ để bóc vỏ EF.SOD và duyệt cây
 * DG13 do Việt Nam tự định nghĩa. Không dùng thư viện ngoài để tránh phụ thuộc
 * vào chi tiết nội bộ của JMRTD.
 */
object Tlv {

  data class Node(
    val tag: Int,
    val constructed: Boolean,
    val value: ByteArray,
    val children: List<Node>,
  ) {
    override fun equals(other: Any?): Boolean =
      this === other || (other is Node && tag == other.tag && value.contentEquals(other.value))

    override fun hashCode(): Int = 31 * tag + value.contentHashCode()
  }

  /** Parse một dãy TLV liền kề ở cùng một mức. */
  fun parse(data: ByteArray, from: Int = 0, to: Int = data.size): List<Node> {
    val nodes = mutableListOf<Node>()
    var offset = from
    while (offset < to) {
      // --- tag ---
      val firstTagByte = data[offset].toInt() and 0xFF
      if (firstTagByte == 0x00 || firstTagByte == 0xFF) { // padding
        offset++
        continue
      }
      var tag = firstTagByte
      var cursor = offset + 1
      if (firstTagByte and 0x1F == 0x1F) {
        // Tag nhiều byte: tiếp tục khi bit 8 = 1.
        do {
          if (cursor >= to) return nodes
          val b = data[cursor].toInt() and 0xFF
          tag = (tag shl 8) or b
          cursor++
        } while (b and 0x80 != 0)
      }
      val constructed = firstTagByte and 0x20 != 0

      // --- length ---
      if (cursor >= to) return nodes
      var length: Int
      val firstLenByte = data[cursor].toInt() and 0xFF
      cursor++
      if (firstLenByte and 0x80 == 0) {
        length = firstLenByte
      } else {
        val numBytes = firstLenByte and 0x7F
        if (numBytes == 0 || numBytes > 4 || cursor + numBytes > to) return nodes
        length = 0
        repeat(numBytes) {
          length = (length shl 8) or (data[cursor].toInt() and 0xFF)
          cursor++
        }
      }
      if (length < 0 || cursor + length > to) return nodes

      val value = data.copyOfRange(cursor, cursor + length)
      val children = if (constructed) parse(data, cursor, cursor + length) else emptyList()
      nodes.add(Node(tag, constructed, value, children))
      offset = cursor + length
    }
    return nodes
  }

  /** Tìm node đầu tiên có tag cho trước ở bất kỳ độ sâu nào. */
  fun findFirst(nodes: List<Node>, tag: Int): Node? {
    for (node in nodes) {
      if (node.tag == tag) return node
      findFirst(node.children, tag)?.let { return it }
    }
    return null
  }

  /**
   * Bóc lớp vỏ ngoài của EF.SOD (`[APPLICATION 23]`, tag `0x77`) để lấy
   * ContentInfo dạng DER dùng cho CMS.
   */
  fun unwrapSod(sodBytes: ByteArray): ByteArray {
    val nodes = parse(sodBytes)
    val outer = nodes.firstOrNull() ?: return sodBytes
    return if (outer.tag == 0x77) outer.value else sodBytes
  }
}

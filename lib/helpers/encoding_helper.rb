# encoding: ascii-8bit

require_relative 'hash_helper'

module EncodingHelper
  BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

  def from_bytes(bytes, endianness)
    bytes = bytes.unpack('C*')
    bytes.reverse! if endianness == 'big'
    bytes.map.with_index { |byte, index| byte * 256**index }.sum
  end

  def from_hex_to_bytes(hex)
    [hex.strip].pack("H*")
  end

  def bytes_to_hex(bytes)
    bytes.unpack1("H*")
  end

  def to_bytes(integer, bytes, endianness)
    byte_array = [0] * bytes
    integer.digits(256).each_with_index do |byte, index|
      byte_array[index] = byte
    end
    byte_array.reverse! if endianness == 'big'
    byte_array.pack('c*')
  end

  def encode_base58(bytes)
    zero_prefix_length = 0
    bytes.each_char { |char| char == "\x00" ? zero_prefix_length += 1 : break }

    num = from_bytes(bytes, 'big')
    prefix = '1' * zero_prefix_length
    prefix + num.digits(58).reverse.map { |d| BASE58_ALPHABET[d] }.join
  end

  def encode_base58_checksum(bytes)
    encode_base58(bytes + HashHelper.hash256(bytes).slice(0, 4))
  end

  def decode_base58(string)
    zero_prefix_length = 0
    string.each_char { |char| char == '1' ? zero_prefix_length += 1 : break }
    num = base58_to_num(string)
    prefix = "\x00" * zero_prefix_length
    combined = prefix + to_bytes(num, num.digits(256).count, 'big')
    checksum = combined.slice(-4, 4)
    message = combined.slice(0, combined.length - 4)
    computed_hash = HashHelper.hash256(message).slice(0, 4)
    if computed_hash != checksum
      raise StandardError.new "bad address: #{checksum} #{computed_hash}"
    end

    message
  end

  def little_endian_to_int(bytes)
    from_bytes(bytes, 'little')
  end

  def int_to_little_endian(int, length)
    to_bytes(int, length, 'little')
  end

  def int_to_big_endian(int, length)
    to_bytes(int, length, 'big')
  end

  def encode_varint(integer)
    if integer < 0xfd
      int_to_little_endian(integer, 1)
    elsif integer < 0x10000
      "\xfd#{int_to_little_endian(integer, 2)}"
    elsif integer < 0x100000000
      "\xfe#{int_to_little_endian(integer, 4)}"
    elsif integer < 0x10000000000000000
      "\xff#{int_to_little_endian(integer, 8)}"
    else
      raise EncodingError.new("integer too large: #{integer}")
    end
  end

  def bit_field_to_bytes(bit_field)
    raise EncodingError.new("bit_field's length is not divisible by 8") if bit_field.length % 8 != 0

    result = [0] * (bit_field.length / 8)
    bit_field.each_with_index do |bit, index|
      byte_index, bit_index = index.divmod(8)
      result[byte_index] |= 1 << bit_index unless bit.zero?
    end
    result.pack('c*')
  end

  def bytes_to_bit_field(bytes)
    bytes = bytes.unpack('C*')
    bit_field = []
    bytes.each do |byte|
      8.times do
        bit_field << (byte & 1)
        byte >>= 1
      end
    end
    bit_field
  end

  private

  def base58_to_num(base58_string)
    num = 0
    base58_string.each_char do |char|
      num *= 58
      num += BASE58_ALPHABET.index char
    end
    num
  end
end

require_relative '../helpers/encoding_helper'
module ECC
  class Signature
    include EncodingHelper
    extend EncodingHelper
    attr_reader :r, :s

    def initialize(r, s)
      @r = r
      @s = s
    end

    def ==(other)
      @r == other.r && @s == other.s
    end

    def to_s
      "Signature(#{@r}, #{s})"
    end

    def der
      rbin = formatted_to_sec(@r)
      result = "\x02#{to_bytes(rbin.length, rbin.length.digits(256).length, 'big')}#{rbin}"
      sbin = formatted_to_sec(@s)
      result += "\x02#{to_bytes(sbin.length, sbin.length.digits(256).length, 'big')}#{sbin}"
      "\x30#{to_bytes(result.length, result.length.digits(256).length, 'big')}#{result}"
    end

    def self.parse(signature_bin)
      signature_length = signature_bin.length
      raise SignatureError.new "First byte must be \x30" if signature_bin.slice!(0) != "\x30"

      length = from_bytes(signature_bin.slice!(0), 'big')
      raise SignatureError.new 'Bad signature length' if length + 2 != signature_length

      check_sec_marker(signature_bin.slice!(0))

      signature_bin, r_length, r = get_vals_from_sec_bin(signature_bin)
      check_sec_marker(signature_bin.slice!(0))

      _, s_length, s = get_vals_from_sec_bin(signature_bin)
      raise SignatureError.new 'Signature too long' if signature_length != 6 + r_length + s_length

      new(r, s)
    end

    private

    def formatted_to_sec(elem)
      bin_elem = to_bytes(elem, 32, 'big')
      bin_elem = bin_elem.reverse.chomp("\x00").reverse
      bin_elem[0].unpack1('C') > 128 ? "\x00#{bin_elem}" : bin_elem
    end

    def self.check_sec_marker(marker)
      raise SignatureError.new "expected marker to be \x02" if marker != "\x02"
    end

    def self.get_vals_from_sec_bin(signature_bin)
      r_length = from_bytes(signature_bin.slice!(0), 'big')
      r = from_bytes(signature_bin.slice!(0, r_length), 'big')
      [signature_bin, r_length, r]
    end

    private_class_method :check_sec_marker, :get_vals_from_sec_bin
  end

  class SignatureError < StandardError; end
end

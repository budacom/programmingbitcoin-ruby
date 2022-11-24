require_relative '../helpers/hash_helper'
require_relative '../helpers/encoding_helper'
require_relative 'network/messages/generic'

module Bitcoin
  class BloomFilter
    include EncodingHelper
    BIP37_CONSTANT = 0xfba4c795

    def initialize(size, function_count, tweak)
      @size = size
      @bit_field = [0] * (size * 8)
      @function_count = function_count
      @tweak = tweak
    end

    attr_reader :bit_field

    def add(item)
      @function_count.times do |i|
        seed = i * BIP37_CONSTANT + @tweak

        hash_result = HashHelper.murmur3(item, seed: seed)
        bit = hash_result % (@size * 8)
        @bit_field[bit] = 1
      end
    end

    def filter_bytes
      bit_field_to_bytes(@bit_field)
    end

    def filterload(flag: 1)
      result = encode_varint(@size)
      result += filter_bytes
      result += int_to_little_endian(@function_count, 4)
      result += int_to_little_endian(@tweak, 4)
      result += int_to_little_endian(flag, 1)

      Bitcoin::Network::Messages::Generic.new('filterload', result)
    end
  end
end

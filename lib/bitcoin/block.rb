require_relative '../bitcoin_data_io'
require_relative '../helpers/encoding_helper'
require_relative '../helpers/hash_helper'

module Bitcoin
  class Block
    include EncodingHelper
    extend EncodingHelper

    GENESIS_BLOCK = from_hex_to_bytes('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
    TESTNET_GENESIS_BLOCK = from_hex_to_bytes('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
    LOWEST_BITS = from_hex_to_bytes('ffff001d')

    MAX_TARGET = 0xffff * 256**(0x1d - 3)
    TWO_WEEKS = 60 * 60 * 24 * 14

    def initialize(version, prev_block, merkle_root, timestamp, bits, nonce)
      @version = version
      @prev_block = prev_block
      @merkle_root = merkle_root
      @timestamp = timestamp
      @bits = bits
      @nonce = nonce
    end

    attr_accessor :version, :prev_block, :merkle_root, :timestamp, :bits, :nonce

    def self.parse(io)
      io = BitcoinDataIO(io)

      version = little_endian_to_int(io.read(4))
      prev_block = io.read_le(32)
      merkle_root = io.read_le(32)
      timestamp = little_endian_to_int(io.read(4))
      bits = io.read(4)
      nonce = io.read(4)

      new(version, prev_block, merkle_root, timestamp, bits, nonce)
    end

    def self.target_to_bits(target)
      raw_bytes = to_bytes(target, 32, 'big').sub(/^\x00*/, "")
      if little_endian_to_int(raw_bytes[0]) > 0x7f
        exponent = raw_bytes.length + 1
        coefficient = "x\00#{raw_bytes[0...2]}"
      else
        exponent = raw_bytes.length
        coefficient = raw_bytes[0...3]
      end
      coefficient.reverse + to_bytes(exponent, 1, 'little')
    end

    def self.bits_to_target(bits)
      exponent = little_endian_to_int(bits[-1])
      coefficient = little_endian_to_int(bits[0...-1])
      coefficient * 256**(exponent - 3)
    end

    def self.calculate_new_bits(previous_bits, time_differential)
      max_differential = 4 * TWO_WEEKS
      time_differential = max_differential if time_differential > max_differential

      min_differential = TWO_WEEKS / 4
      time_differential = min_differential if time_differential < min_differential

      previous_target = Block.bits_to_target(previous_bits)
      new_target = previous_target * time_differential / TWO_WEEKS

      new_target = MAX_TARGET if new_target > MAX_TARGET
      Block.target_to_bits(new_target)
    end

    def serialize
      result = to_bytes(version, 4, 'little')
      result << prev_block.reverse
      result << merkle_root.reverse
      result << to_bytes(timestamp, 4, 'little')
      result << bits
      result << nonce
    end

    def hash
      HashHelper.hash256(serialize).reverse
    end

    def bip9?
      version >> 29 == 0b001
    end

    def bip91?
      (version >> 4) & 1 == 1
    end

    def bip141?
      (version >> 1) & 1 == 1
    end

    def target
      Block.bits_to_target(bits)
    end

    def difficulty
      MAX_TARGET / target
    end

    def pow_valid?
      block_header_hash = HashHelper.hash256(serialize)
      little_endian_to_int(block_header_hash) < target
    end
  end
end

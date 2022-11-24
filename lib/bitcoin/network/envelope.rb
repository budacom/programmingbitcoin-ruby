# encoding: ascii-8bit

require_relative '../../bitcoin_data_io'
require_relative '../../helpers/encoding_helper'
require_relative '../../helpers/hash_helper'

module Bitcoin
  module Network
    class Envelope
      include EncodingHelper
      extend EncodingHelper

      NETWORK_MAGIC = "f9beb4d9"
      TESTNET_NETWORK_MAGIC = "0b110907"

      def initialize(command, payload, testnet=false)
        @command_bytes = command
        @payload_bytes = payload
        @magic_hex = testnet ? TESTNET_NETWORK_MAGIC : NETWORK_MAGIC
      end

      attr_accessor :command_bytes, :payload_bytes, :magic_hex

      def self.parse(io)
        bitcoin_io = BitcoinDataIO(io)
        network_magic_bytes = bitcoin_io.read(4)
        raise IOError.new('no data received') if network_magic_bytes.nil?

        network_magic = bytes_to_hex(network_magic_bytes)
        raise IOError.new('unrecognized network magic') unless [
          NETWORK_MAGIC, TESTNET_NETWORK_MAGIC
        ].include? network_magic

        command = bitcoin_io.read(12).delete("\x00")
        payload_length = bitcoin_io.read_le_int32
        checksum = bitcoin_io.read(4)
        payload = bitcoin_io.read(payload_length) || ''

        raise IOError.new("checksum doesn't match") unless checksum_match?(payload, checksum)

        new(command, payload, network_magic == TESTNET_NETWORK_MAGIC)
      end

      def self.checksum(payload)
        HashHelper.hash256(payload).slice(0, 4)
      end

      def self.checksum_match?(payload, _checksum)
        checksum(payload) == _checksum
      end

      def to_s
        "#{@command_bytes}: #{@payload_bytes}"
      end

      def serialize
        result = from_hex_to_bytes(@magic_hex)
        result << @command_bytes
        result << "\x00" * (12 - @command_bytes.length)
        result << int_to_little_endian(@payload_bytes.length, 4)
        result << self.class.checksum(@payload_bytes)
        result << @payload_bytes

        result
      end

      def stream
        StringIO.new(@payload_bytes)
      end

      private_class_method :checksum_match?
    end
  end
end

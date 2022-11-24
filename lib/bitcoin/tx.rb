require_relative '../bitcoin_data_io'
require_relative '../helpers/encoding_helper'
require_relative '../helpers/hash_helper'
require_relative './fetcher/uri_fetcher'
require_relative 'script'
require 'net/http'
require 'uri'
require 'stringio'

module Bitcoin
  class Tx
    include EncodingHelper
    SIGHASH_ALL = 1
    SIGHASH_NONE = 2
    SIGHASH_SINGLE = 3

    class TxIn
      include EncodingHelper

      def initialize(prev_tx, prev_index, script_sig = nil, sequence = 0xffffffff)
        @prev_tx = prev_tx
        @prev_index = prev_index
        @script_sig = script_sig || Script.new
        @sequence = sequence
        @tx_fetcher = UriFetcher.new
      end

      def self.parse(_io)
        io = BitcoinDataIO(_io)

        prev_tx = io.read_le(32)
        prev_index = io.read_le_int32
        script_sig = Script.parse io
        sequence = io.read_le_int32

        new(prev_tx, prev_index, script_sig, sequence)
      end

      def fetch_tx(testnet: false)
        tx_id = prev_tx.unpack1('H*')

        @tx_fetcher.fetch tx_id, testnet: testnet
      end

      def script_pubkey(testnet: false)
        tx = fetch_tx testnet: testnet
        tx.outs[prev_index].script_pubkey
      end

      def serialize
        result = prev_tx.reverse
        result << to_bytes(prev_index, 4, 'little')
        result << @script_sig.serialize
        result << to_bytes(sequence, 4, 'little')
      end

      attr_accessor :prev_tx, :prev_index, :script_sig, :sequence
    end

    class TxOut
      include EncodingHelper

      def self.parse(_io)
        io = BitcoinDataIO(_io)

        new.tap do |obj|
          obj.amount = io.read_le_int64
          obj.script_pubkey = Script.parse io
        end
      end

      def serialize
        int_to_little_endian(@amount, 8) + @script_pubkey.serialize
      end

      attr_accessor :amount, :script_pubkey
    end

    def self.parse(_io, _options = {})
      io = BitcoinDataIO(_io)

      new(_options).tap do |tx|
        tx.version = io.read_le_int32
        io.read_varint.times { tx.ins << TxIn.parse(io) }
        io.read_varint.times { tx.outs << TxOut.parse(io) }
        tx.locktime = io.read_le_int32
      end
    end

    def id
      HashHelper.hash256(serialize).reverse.unpack('H*')
    end

    def serialize
      result = to_bytes(version, 4, 'little')
      result << encode_varint(ins.size)
      result << ins.map(&:serialize).join
      result << encode_varint(outs.size)
      result << outs.map(&:serialize).join
      result << to_bytes(locktime, 4, 'little')

      result
    end

    attr_accessor :version, :locktime, :ins, :outs

    def initialize(tx_fetcher: nil, testnet: false)
      @tx_fetcher = tx_fetcher
      @ins = []
      @outs = []
      @testnet = testnet
    end

    def fee
      @fee ||= calculate_fee
    end

    def sig_hash(input_index, redeem_script = nil)
      result = int_to_little_endian(version, 4)
      result << encode_ins(input_index, redeem_script)
      result << encode_outs
      result << int_to_little_endian(locktime, 4)
      result << int_to_little_endian(SIGHASH_ALL, 4)

      hash256 = HashHelper.hash256 result

      from_bytes hash256, 'big'
    end

    def verify_input(input_index)
      tx_in = ins[input_index]
      script_pubkey = tx_in.script_pubkey testnet: @testnet

      if script_pubkey.p2sh?
        cmd = tx_in.script_sig.cmds[-1]
        raw_redeem = encode_varint(cmd.length) + cmd
        redeem_script = Script.parse(StringIO.new(raw_redeem))
      else
        redeem_script = nil
      end
      z = sig_hash(input_index, redeem_script)
      combined = tx_in.script_sig + script_pubkey
      combined.evaluate(z)
    end

    def verify?
      return false if @fee.negative?

      ins.each_with_index do |_, index|
        return false unless verify_input index
      end

      true
    end

    def sign_input(input_index, private_key)
      z = sig_hash(input_index)
      der = private_key.sign(z).der
      sig = der + to_bytes(SIGHASH_ALL, 1, 'big')
      sec = private_key.point.sec()
      ins[input_index].script_sig = Script.new([sig, sec])

      verify_input(input_index)
    end

    def coinbase?
      return false unless ins.size == 1

      tx_in = ins.first
      return false unless tx_in.prev_tx == "\x00" * 32

      tx_in.prev_index == 0xffffffff
    end

    def coinbase_height
      return nil unless coinbase?

      first_cmd = ins[0].script_sig.cmds[0]
      little_endian_to_int(first_cmd)
    end

    private

    def encode_ins(input_index, redeem_script)
      result = encode_varint(ins.size)

      ins.each_with_index do |input, index|
        script_sig = if index == input_index
                       redeem_script || input.script_pubkey(testnet: @testnet)
                     end

        result << TxIn.new(
          input.prev_tx,
          input.prev_index,
          script_sig,
          input.sequence
        ).serialize
      end

      result
    end

    def encode_outs
      encode_varint(outs.size) + outs.map(&:serialize).join
    end

    def calculate_fee
      raise 'transaction fetcher not provided' if @tx_fetcher.nil?

      input_amount = ins.sum do |input|
        raw_input_tx = @tx_fetcher.fetch(input.prev_tx)
        input_tx = Bitcoin::Tx.parse(raw_input_tx)
        input_tx.outs[input.prev_index].amount
      end

      output_amount = outs.sum(&:amount)

      input_amount - output_amount
    end
  end
end

require_relative '../bitcoin_data_io'
require_relative '../encoding_helper'
require_relative '../hash_helper'
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

      def initialize(prev_tx, prev_index, script_sig = nil, sequence = 0xffffffff, witness = nil)
        @prev_tx = prev_tx
        @prev_index = prev_index
        @script_sig = script_sig || Script.new
        @sequence = sequence
        @tx_fetcher = UriFetcher.new
        @witness = witness
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

      def value(testnet: false)
        tx = fetch_tx testnet: testnet
        tx.outs[prev_index].amount
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

      def serialize_witness
        result = int_to_little_endian(@witness.size, 1)
        @witness.each do |wt|
          result << if wt.is_a?(Integer)
                      int_to_little_endian(wt, 1)
                    else
                      encode_varint(wt.size) + wt
                    end
        end
        result
      end

      attr_accessor :prev_tx, :prev_index, :script_sig, :sequence, :witness
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
      segwit?(_io) ? parse_segwit(_io, _options) : parse_legacy(_io, _options)
    end

    def self.parse_legacy(_io, _options)
      io = BitcoinDataIO(_io)

      new(_options).tap do |tx|
        tx.version = io.read_le_int32
        io.read_varint.times { tx.ins << TxIn.parse(io) }
        io.read_varint.times { tx.outs << TxOut.parse(io) }
        tx.locktime = io.read_le_int32
      end
    end

    def self.parse_segwit(_io, _options)
      io = BitcoinDataIO(_io)

      new(_options).tap do |tx|
        tx.version = io.read_le_int32
        marker = io.read(2)
        raise "Not a segwit transaction #{marker}" unless marker == "\x00\x01"

        io.read_varint.times { tx.ins << TxIn.parse(io) }
        io.read_varint.times { tx.outs << TxOut.parse(io) }
        tx.read_witness_items(io)
        tx.locktime = io.read_le_int32
        tx.segwit = true
      end
    end

    def self.segwit?(_io)
      _io.read(4)
      flag_byte = _io.read(1)
      _io.rewind

      flag_byte == "\x00"
    end

    def read_witness_items(_io)
      @ins.each do |tx_in|
        items = []
        _io.read_varint.times do
          item_len = _io.read_varint
          items << if item_len.zero?
                     0
                   else
                     _io.read(item_len)
                   end
        end
        tx_in.witness = items
      end
    end

    def id
      HashHelper.hash256(serialize_legacy).reverse.unpack('H*')
    end

    def serialize
      segwit ? serialize_segwit : serialize_legacy
    end

    # rubocop:disable Metrics/AbcSize
    def serialize_segwit
      result = to_bytes(version, 4, 'little')
      result << "\x00\x01"
      result << encode_varint(ins.size)
      result << ins.map(&:serialize).join
      result << encode_varint(outs.size)
      result << outs.map(&:serialize).join
      result << ins.map(&:serialize_witness).join
      result << to_bytes(locktime, 4, 'little')

      result
    end
    # rubocop:enable Metrics/AbcSize

    def serialize_legacy
      result = to_bytes(version, 4, 'little')
      result << encode_varint(ins.size)
      result << ins.map(&:serialize).join
      result << encode_varint(outs.size)
      result << outs.map(&:serialize).join
      result << to_bytes(locktime, 4, 'little')

      result
    end

    attr_accessor :version, :locktime, :ins, :outs, :segwit,
                  :_hash_prevouts, :_hash_sequence, :_hash_outputs

    def initialize(tx_fetcher: nil, testnet: false, segwit: false)
      @tx_fetcher = tx_fetcher
      @ins = []
      @outs = []
      @testnet = testnet
      @segwit = segwit
      @_hash_prevouts = nil
      @_hash_sequence = nil
      @_hash_outputs = nil
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

    # rubocop:disable Metrics/AbcSize
    def sig_hash_bip143(input_index, redeem_script: nil, witness_script: nil)
      tx_in = @ins[input_index]
      result = int_to_little_endian(version, 4)

      result += hash_prevouts + hash_sequence
      result += tx_in.prev_tx.reverse + int_to_little_endian(tx_in.prev_index, 4)
      result += build_script_raw(redeem_script, witness_script, tx_in)
      result += int_to_little_endian(tx_in.value, 8)
      result += int_to_little_endian(tx_in.sequence, 4)
      result += hash_outputs
      result << int_to_little_endian(locktime, 4)
      result << int_to_little_endian(SIGHASH_ALL, 4)

      hash256 = HashHelper.hash256 result

      from_bytes hash256, 'big'
    end
    # rubocop:enable Metrics/AbcSize

    def hash_prevouts
      unless @_hash_prevouts
        all_prevouts = ''
        all_sequence = ''
        @ins.each do |tx_in|
          all_prevouts += tx_in.prev_tx.reverse + int_to_little_endian(tx_in.prev_index, 4)
          all_sequence += int_to_little_endian(tx_in.sequence, 4)
        end
        @_hash_prevouts = HashHelper.hash256(all_prevouts)
        @_hash_sequence = HashHelper.hash256(all_sequence)
      end
      @_hash_prevouts
    end

    def hash_sequence
      hash_prevouts unless @_hash_sequence
      @_hash_sequence
    end

    def hash_outputs
      unless @_hash_outputs
        all_outputs = ''
        @outs.each { |tx_out| all_outputs += tx_out.serialize }
        @_hash_outputs = HashHelper.hash256(all_outputs)
      end
      @_hash_outputs
    end

    def verify_input(input_index)
      tx_in = ins[input_index]
      script_pubkey = tx_in.script_pubkey testnet: @testnet
      z, witness = build_z_and_witness(script_pubkey, tx_in, input_index)

      combined = tx_in.script_sig + script_pubkey
      combined.evaluate(z, witness: witness)
    end

    def build_z_and_witness(script_pubkey, tx_in, input_index) # rubocop:disable Metrics/MethodLength
      if script_pubkey.p2sh?
        cmd = tx_in.script_sig.cmds[-1]
        raw_redeem = encode_varint(cmd.length) + cmd
        redeem_script = Script.parse(StringIO.new(raw_redeem))

        if redeem_script.p2wpkh?
          [sig_hash_bip143(input_index, redeem_script), tx_in.witness]
        elsif redeem_script.p2wsh?
          build_z_from_witness(tx_in, input_index)
        else
          [sig_hash(input_index, redeem_script), nil]
        end

      elsif script_pubkey.p2wpkh?
        [sig_hash_bip143(input_index, redeem_script: redeem_script), tx_in.witness]
      elsif script_pubkey.p2wsh?
        build_z_from_witness(tx_in, input_index)
      else
        [sig_hash(input_index), nil]
      end
    end

    def build_z_from_witness(tx_in, input_index)
      cmd = tx_in.witness.last
      raw_witness = encode_varint(cmd.size) + cmd
      witness_script = Script.parse(StringIO.new(raw_witness))

      [sig_hash_bip143(input_index, witness_script: witness_script), tx_in.witness]
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

    def build_script_raw(redeem_script, witness_script, tx_in)
      if witness_script
        witness_script.serialize
      elsif redeem_script
        Script.p2pkh(redeem_script.cms[1]).serialize
      else
        Script.p2pkh(tx_in.script_pubkey(testnet: @testnet).cmds[1]).serialize
      end
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

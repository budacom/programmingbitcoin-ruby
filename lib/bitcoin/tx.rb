require_relative '../bitcoin_data_io'

module Bitcoin
  include EncodingHelper

  class Tx
    class TxIn
      def self.parse(_io )
        io = BitcoinDataIO(_io)

        new.tap do |obj|
          obj.prev_tx = io.read_le(32)
          obj.prev_index = io.read_le_int32
          obj.raw_script_sig = _io.read(io.read_varint)
          obj.sequence = io.read_le_int32
        end
      end

      attr_accessor :prev_tx, :prev_index, :raw_script_sig, :sequence
    end

    class TxOut
      def self.parse(_io)
        io = BitcoinDataIO(_io)

        new.tap do |obj|
          obj.amount = io.read_le_int64
          obj.raw_script_pubkey = _io.read(io.read_varint)
        end
      end

      attr_accessor :amount, :raw_script_pubkey
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

    attr_accessor :version, :locktime, :ins, :outs

    def initialize(tx_fetcher: nil)
      @tx_fetcher = tx_fetcher
      @ins = []
      @outs = []
    end

    def fee
      @fee ||= calculate_fee
    end

    def sig_hash(input_index)
      result = int_to_little_endian version, 4
      result << encode_varint ins.size 
      
      ins.each_with_index do |input, index|
        if index == input_index
          result << TxIn.new(
            prev_tx: input.prev_tx,
            prev_index: input.prev_index,
            raw_script_sig: input.raw_script_sig, # TODO: add script_pubkey
            sequence: input.sequence
          ) # TODO: add serialize
        else
          result << TxIn.new(
            prev_tx: input.prev_tx,
            prev_index: input.prev_index,
            sequence: input.sequence
          ) # TODO: add serialize
        end
      end

      result << encode_varint outs.size
      outs.each do |output|
        result << output # TODO: add serialize
      end

      result << int_to_little_endian locktime, 4
      result << int_to_little_endian SIGHASH_ALL, 4
      hash256 = HashHelper.hash256 result

      from_bytes hash256, 'big'
    end

    private

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

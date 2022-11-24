require 'helpers/encoding_helper'
require 'bitcoin_data_io'

RSpec.describe BitcoinDataIO do
  def io(_hex_data)
    described_class.new(StringIO.new([_hex_data].pack("H*")))
  end

  describe '#read_le' do
    it "reads given number of bytes and returns them in little-endian ordering" do
      expect(bytes_to_hex(io('aabbcc').read_le(2))).to eq 'bbaa'
    end
  end

  describe '#read_le_int16' do
    it "reads the next 2 bytes as a little-endian number" do
      expect(io('0201ff').read_le_int16).to eq 0x102
    end
  end

  describe '#read_le_int32' do
    it "reads the next 4 bytes as a little-endian number" do
      expect(io('04030201ff').read_le_int32).to eq 0x1020304
    end
  end

  describe '#read_le_int64' do
    it "reads the next 8 bytes as a little-endian number" do
      expect(io('0807060504030201ff').read_le_int64).to eq 0x102030405060708
    end
  end

  describe '#read_varint' do
    it "properly reads the next 1 byte varint" do
      expect(io('08ff').read_varint).to eq 0x8
    end

    it "properly reads the next 2 byte varint" do
      expect(io('fd0201ff').read_varint).to eq 0x102
    end

    it "properly reads the next 4 byte varint" do
      expect(io('fe04030201ff').read_varint).to eq 0x1020304
    end

    it "properly reads the next 8 byte varint" do
      expect(io('ff0807060504030201ff').read_varint).to eq 0x102030405060708
    end
  end

  def bytes_to_hex(_bytes)
    _bytes.unpack1("H*")
  end
end

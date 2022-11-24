require_relative '../../lib/bitcoin/bloom_filter'
require_relative '../../lib/helpers/encoding_helper'

RSpec.describe Bitcoin::BloomFilter do
  include EncodingHelper

  describe '.new' do
    it 'initializes the bit_field appropiately' do
      expect(described_class.new(1, 2, 3).bit_field).to eq [0] * 8
    end
  end

  describe '#add' do
    it 'mutates the bit_field correctly' do
      expected_bit_field = bytes_to_bit_field(from_hex_to_bytes('0000000a080000000140'))
      bloom_filter = described_class.new(10, 5, 99)
      expect { bloom_filter.add('Hello World') }
        .to((change { bloom_filter.bit_field }.to expected_bit_field))
    end
  end

  describe '#filter_bytes' do
    it 'returns the proper filter bytes' do
      bloom_filter = described_class.new(10, 5, 99)
      expect(bloom_filter.filter_bytes).to eq bit_field_to_bytes([0] * 10 * 8)
      bloom_filter.add('Hello World')
      expect(bloom_filter.filter_bytes).to eq from_hex_to_bytes('0000000a080000000140')
      bloom_filter.add('Goodbye!')
      expect(bloom_filter.filter_bytes).to eq from_hex_to_bytes('4000600a080000010940')
    end
  end

  describe '#filterload' do
    it 'returns the proper generic filterload message' do
      bloom_filter = described_class.new(10, 5, 99)
      bloom_filter.add('Hello World')
      bloom_filter.add('Goodbye!')
      expect(bloom_filter.filterload.command).to eq 'filterload'
      expect(bloom_filter.filterload.serialize)
        .to eq from_hex_to_bytes('0a4000600a080000010940050000006300000001')
    end
  end
end

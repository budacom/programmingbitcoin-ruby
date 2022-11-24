require 'bitcoin/block'
require 'helpers/encoding_helper'

RSpec.describe Bitcoin::Block do
  include EncodingHelper

  let(:raw_block_header) do
    from_hex_to_bytes(
      "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40\
508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d"
    )
  end

  let(:block_header) do
    described_class.new(
      0x20000002,
      from_hex_to_bytes('000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e'),
      from_hex_to_bytes('be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b'),
      0x59a7771e,
      from_hex_to_bytes('e93c0118'),
      from_hex_to_bytes('a4ffd71d')
    )
  end

  describe '.parse' do
    def parse(*args)
      described_class.parse(StringIO.new(*args))
    end

    it 'properly parses the version' do
      expect(parse(raw_block_header).version).to eq block_header.version
    end

    it 'properly parses the previous block' do
      expect(parse(raw_block_header).prev_block).to eq block_header.prev_block
    end

    it 'properly parses the merkle root' do
      expect(parse(raw_block_header).merkle_root).to eq block_header.merkle_root
    end

    it 'properly parses the timestamp' do
      expect(parse(raw_block_header).timestamp).to eq block_header.timestamp
    end

    it 'properly parses the bits' do
      expect(parse(raw_block_header).bits).to eq block_header.bits
    end

    it 'properly parses the nonce' do
      expect(parse(raw_block_header).nonce).to eq block_header.nonce
    end
  end

  describe '.target_to_bits' do
    it 'returns a target integer back into bits' do
      expect(described_class.target_to_bits(0x13ce9000000000000000000000000000000000000000000))
        .to eq from_hex_to_bytes('e93c0118')
    end
  end

  describe '.bits_to_target' do
    it 'computes the target for the given bits' do
      expect(described_class.bits_to_target(block_header.bits))
        .to eq 0x13ce9000000000000000000000000000000000000000000
    end
  end

  describe '.calculate_new_bits' do
    it 'computes the new bits 2016-block time differential and the previous bits' do
      expect(described_class.calculate_new_bits(from_hex_to_bytes('54d80118'), 302400))
        .to eq from_hex_to_bytes('00157617')
    end
  end

  describe '#serialize' do
    it { expect(block_header.serialize).to eq raw_block_header }
  end

  describe '#hash' do
    let(:hex_hash) { '0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523' }

    it { expect(block_header.hash).to eq from_hex_to_bytes(hex_hash) }
  end

  describe '#bip9?' do
    context 'with bip9 block' do
      it { expect(block_header.bip9?).to be true }
    end

    context 'with non bip9 block' do
      before { block_header.version = 0x01000000 }

      it { expect(block_header.bip9?).to be false }
    end
  end

  describe '#bip91?' do
    context 'with non bip91 block' do
      it { expect(block_header.bip91?).to be false }
    end

    context 'with bip91 block' do
      before { block_header.version = 0x01000010 }

      it { expect(block_header.bip91?).to be true }
    end
  end

  describe '#bip141?' do
    context 'with bip141 block' do
      it { expect(block_header.bip141?).to be true }
    end

    context 'with non bip141 block' do
      before { block_header.version = 0x01000000 }

      it { expect(block_header.bip141?).to be false }
    end
  end

  describe '#target' do
    it { expect(block_header.target).to eq 0x13ce9000000000000000000000000000000000000000000 }
  end

  describe '#difficulty' do
    it { expect(block_header.difficulty).to eq 888171856257 }
  end

  describe '#pow_valid?' do
    context 'with valid PoW' do
      it { expect(block_header.pow_valid?).to be true }
    end

    context 'with invalid PoW' do
      before { block_header.nonce = from_hex_to_bytes('00000000') }

      it { expect(block_header.pow_valid?).to be false }
    end
  end
end

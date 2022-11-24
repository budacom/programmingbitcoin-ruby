require 'helpers/hash_helper'

RSpec.describe HashHelper do
  describe '.hash160' do
    it 'computes the hash by sha256 followed by ripemd160' do
      hash = '77bc43ce98ed7de19a42b6f2b8978df300890a2d'
      expect(described_class.hash160('Bitcoin Guild rocks!').unpack1('H*')).to eq(hash)
    end
  end

  describe '.hash256' do
    it 'computes the hash by two passes of sha256' do
      hash = 'a63898c9855b802d6db18886928affbc22b928c3ccd683e21d62da8f0af00a42'
      expect(described_class.hash256('Bitcoin Guild rocks!').unpack1('H*')).to eq(hash)
    end
  end

  describe '.murmur3' do
    it 'computes the correct murmur3 hash for different message and seeds' do
      [1203516251, 669393163, 819509628, 3765971536].each_with_index do |expected_hash, seed|
        expect(described_class.murmur3('Bitcoin Guild rocks!', seed: seed)).to eq(expected_hash)
      end
      expect(described_class.murmur3('Goodbye!', seed: 8443760525)).to eq(468028502)
      [1411415842, 2371772749, 4164319582, 2164673664].each_with_index do |expected_hash, seed|
        expect(described_class.murmur3("Bitcoin Guild rocks! #{seed}")).to eq(expected_hash)
      end
    end
  end
end

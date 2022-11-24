require 'helpers/hash_helper'

RSpec.describe HashHelper do
  describe '#hash160' do
    it 'computes the hash by sha256 followed by ripemd160' do
      hash = '77bc43ce98ed7de19a42b6f2b8978df300890a2d'
      expect(described_class.hash160('Bitcoin Guild rocks!').unpack1('H*')).to eq(hash)
    end
  end

  describe '#hash256' do
    it 'computes the hash by two passes of sha256' do
      hash = 'a63898c9855b802d6db18886928affbc22b928c3ccd683e21d62da8f0af00a42'
      expect(described_class.hash256('Bitcoin Guild rocks!').unpack1('H*')).to eq(hash)
    end
  end
end

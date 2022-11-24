require 'ecc/s256_point'
require 'ecc/s256_field'
require 'ecc/field_element'
require 'ecc/signature'
require 'ecc/secp256k1_constants'
require 'ecc/private_key'
require 'helpers/encoding_helper'
require 'helpers/hash_helper'

RSpec.describe ECC::S256Point do
  describe 'init' do
    context 'when S256Point is initialized but is not part of the curve' do
      let(:x) { 0x887387e452b8eacc4acfde10d9aaf7e6d9a0f975aabb10d006e4da568744d06c }
      let(:y) { 0x61de6d95231cd29026e286df3e6ae4a894a3378e393e93a0f45b666329a0ae34 }

      it 'raises an ArgumentError' do
        expect { described_class.new(x, y) }.to raise_error(ArgumentError)
      end
    end
  end

  describe 'order of group' do
    let(:identity) { Secp256k1Constants::N * described_class::G }

    it 'returns identity point' do
      expect([identity.x, identity.y]).to eq [nil, nil]
    end
  end

  describe 'secret and generator point solves to public point' do
    let(:secret) { 7 }
    let(:x) { 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc }
    let(:y) { 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da }
    let(:point) { described_class.new(x, y) }

    it 'returns public point' do
      expect(secret * described_class::G).to eq point
    end
  end

  describe 'verify' do
    let(:x) { 0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c }
    let(:y) { 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34 }
    let(:point) { described_class.new(x, y) }

    let(:r) { 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395 }
    let(:s) { 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4 }
    let(:signature) { ECC::Signature.new(r, s) }

    let(:z) { 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60 }

    context 'when signature is valid' do
      it 'returns true' do
        expect(point.verify(z, signature)).to be true
      end
    end

    context 'when signature is not valid' do
      let(:r_modified) { 0xac8d1c87eeed0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395 }
      let(:signature_modified) { ECC::Signature.new(r_modified, s) }

      it 'returns false' do
        expect(point.verify(z, signature_modified)).to be false
      end
    end

    context 'when message is altered' do
      let(:z_modified) { 0xec208baa0fc1c194408a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60 }

      it 'returns false' do
        expect(point.verify(z_modified, signature)).to be false
      end
    end
  end

  describe '#sec' do
    it 'returns the binary version of the uncompressed SEC format' do
      pubkey = ECC::PrivateKey.new(5000).point
      sec_bytes_hex = "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e"\
                      "03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10"
      expect(pubkey.sec(compressed: false).unpack1('H*')).to eq(sec_bytes_hex)
    end

    it 'returns the binary version of the compressed SEC format' do
      pubkey = ECC::PrivateKey.new(5000).point
      sec_bytes_hex = "02ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c"
      expect(pubkey.sec(compressed: true).unpack1('H*')).to eq(sec_bytes_hex)
    end
  end

  describe '#hash160' do
    it 'returns the hash160 of the sec encoding' do
      pubkey = ECC::PrivateKey.new(5000).point
      hash = HashHelper.hash160(pubkey.sec(compressed: true))
      expect(pubkey.hash160(compressed: true)).to eq hash
    end
  end

  describe '#address' do
    it 'generates the proper compressed testnet address' do
      pubkey = ECC::PrivateKey.new(888**3).point
      address = 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP'
      expect(pubkey.address(compressed: true, testnet: true)).to eq address
    end

    it 'generates the proper compressed mainnet address' do
      pubkey = ECC::PrivateKey.new(888**3).point
      address = '148dY81A9BmdpMhvYEVznrM45kWN32vSCN'
      expect(pubkey.address(compressed: true, testnet: false)).to eq address
    end

    it 'generates the proper uncompressed testnet address' do
      pubkey = ECC::PrivateKey.new(4242424242).point
      address = 'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s'
      expect(pubkey.address(compressed: false, testnet: true)).to eq address
    end

    it 'generates the proper uncompressed mainnet address' do
      pubkey = ECC::PrivateKey.new(4242424242).point
      address = '1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb'
      expect(pubkey.address(compressed: false, testnet: false)).to eq address
    end
  end

  describe '.parse' do
    it 'returns a Point object from a uncompressed SEC binary' do
      point = ECC::PrivateKey.new(69420).point
      sec_bytes = point.sec(compressed: false)
      expect(described_class.parse(sec_bytes)).to eq point
    end

    it 'returns a Point object from a compressed SEC binary' do
      point = ECC::PrivateKey.new(69420).point
      sec_bytes = point.sec(compressed: true)
      expect(described_class.parse(sec_bytes)).to eq point
    end
  end
end

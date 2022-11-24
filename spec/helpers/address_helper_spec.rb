require 'helpers/address_helper'

RSpec.describe AddressHelper do
  let(:described_module) { Object.new.extend described_class }

  describe '#h160_to_p2pkh_address' do
    let(:h160) { ['74d691da1574e6b3c192ecfb52cc8984ee7b6c56'].pack('H*') }

    context 'when testnet is true' do
      let(:testnet) { true }

      it 'calculates the testnet address' do
        expect(described_module.h160_to_p2pkh_address(h160, testnet: testnet))
          .to eq('mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q')
      end
    end

    context 'when testnet is false' do
      let(:testnet) { false }

      it 'calculates the mainnet address' do
        expect(described_module.h160_to_p2pkh_address(h160, testnet: testnet))
          .to eq('1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa')
      end
    end
  end

  describe '#h160_to_p2sh_address' do
    let(:h160) { ['74d691da1574e6b3c192ecfb52cc8984ee7b6c56'].pack('H*') }

    context 'when testnet is true' do
      let(:testnet) { true }

      it 'calculates the testnet address' do
        expect(described_module.h160_to_p2sh_address(h160, testnet: testnet))
          .to eq('2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B')
      end
    end

    context 'when testnet is false' do
      let(:testnet) { false }

      it 'calculates the mainnet address' do
        expect(described_module.h160_to_p2sh_address(h160, testnet: testnet))
          .to eq('3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh')
      end
    end
  end
end

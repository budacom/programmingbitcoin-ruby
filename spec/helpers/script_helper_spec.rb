require 'helpers/script_helper'

RSpec.describe ScriptHelper do
  let(:described_module) { Object.new.extend described_class }

  describe '#encode_num' do
    context 'when the number is 0' do
      let(:num) { 0 }

      it 'returns an empty string' do
        expect(described_module.encode_num(num)).to eq ""
      end
    end

    context 'when the number is not 0' do
      let(:num) { 7 }

      it 'returns the number as a single byte' do
        expect(described_module.encode_num(num)).to eq "\x07"
      end
    end
  end

  describe '#decode_num' do
    context 'when string is empty' do
      let (:str) { '' }

      it 'returns 0' do
        expect(described_module.decode_num(str)).to eq 0
      end
    end

    context 'when string is not empty' do
      let (:str) { 'A02F' }

      it 'returns the little-endian byte sequence of the string ' do
        expect(described_module.decode_num(str)).to eq 1177694273
      end
    end
  end
end

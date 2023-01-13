require 'bitcoin/script'
require 'bitcoin/op'
require 'encoding_helper'
require 'pry'

RSpec.describe Bitcoin::Script do
  def _raw_script(hex_script)
    StringIO.new([hex_script].pack("H*"))
  end

  describe ".parse" do
    context "when the script contains elements" do
      let(:elem_1_hex) { "11" * 5 }
      let(:elem_2_hex) { "11" * 17 }

      it "properly parses the script" do
        raw_script = _raw_script("1805#{elem_1_hex}11#{elem_2_hex}")
        script = described_class.parse(raw_script)

        expect(script.cmds).to eq([
                                    [elem_1_hex].pack("H*"),
                                    [elem_2_hex].pack("H*")
                                  ])
      end
    end

    context "when the script contains an `OP_PUSHDATA1` opcode" do
      let(:data_hex) { "11" * 50 }
      let(:raw_script) { _raw_script("344c32#{data_hex}") }

      it "properly parses the script" do
        script = described_class.parse(raw_script)
        expect(script.cmds).to eq([[data_hex].pack("H*")])
      end
    end

    context "when the script contains an `OP_PUSHDATA2` opcode" do
      let(:data_hex) { "11" * 300 }
      let(:raw_script) { _raw_script("fd2f014d2c01#{data_hex}") }

      it "properly parses the script" do
        script = described_class.parse(raw_script)
        expect(script.cmds).to eq([[data_hex].pack("H*")])
      end
    end

    context "when the script contains any other opcode" do
      let(:raw_script) { _raw_script("034e4f50") }

      it "properly parses the script" do
        script = described_class.parse(raw_script)
        expect(script.cmds).to eq([78, 79, 80])
      end
    end

    context "when the the bytes counter does not match the script length" do
      let(:raw_script) { _raw_script("0506111111111111") }

      it "raises a SyntaxError" do
        expect { described_class.parse(raw_script) }.to raise_error(SyntaxError)
      end
    end
  end

  describe "#serialize" do
    context "when the script contains elements" do
      let(:elem_1_hex) { "11" * 5 }
      let(:elem_2_hex) { "11" * 17 }

      it "properly seriliazes the script" do
        script = described_class.new([
                                       [elem_1_hex].pack("H*"),
                                       [elem_2_hex].pack("H*")
                                     ])

        expected = ["1805#{elem_1_hex}11#{elem_2_hex}"].pack("H*")
        expect(script.serialize).to eq(expected)
      end
    end

    context "when the script contains elements longer than 75 bytes" do
      let(:data_hex) { "11" * 80 }

      it "properly serializes the script" do
        script = described_class.new([[data_hex].pack("H*")])

        expected = ["524c50#{data_hex}"].pack("H*")
        expect(script.serialize).to eq(expected)
      end
    end

    context "when the script contains elements longer than 255 bytes" do
      let(:data_hex) { "11" * 300 }

      it "properly serializes the script" do
        script = described_class.new([[data_hex].pack("H*")])

        expected = ["fd2f014d2c01#{data_hex}"].pack("H*")
        expect(script.serialize).to eq(expected)
      end
    end

    context "when the script contains any other opcode" do
      let(:commands) { [78, 79, 80] }

      it "properly serializes the script" do
        script = described_class.new(commands)

        expected = ["034e4f50"].pack("H*")
        expect(script.serialize).to eq(expected)
      end
    end
  end

  describe "#evaluate" do
    let(:commands) { [] }
    let!(:script) { described_class.new(commands) }

    context "when an operation does not execute successfully" do
      let(:commands) { ["\01", 172] }

      it "returns false" do
        expect(script.evaluate(0x1111)).to be false
      end
    end

    context "when the script finishes with 0 as the top element" do
      let(:commands) { ["\01", "\02", "\03", 118, 0] }

      it "returns false" do
        expect(script.evaluate(0x1111)).to be false
      end
    end

    context "when the script finishes with an empty stack" do
      let(:commands) { ["\01", 117] }

      it "returns false" do
        expect(script.evaluate(0x1111)).to be false
      end
    end

    context "when the script finishes with a nonzero top element" do
      let(:commands) { ["\01", 169, "", 117] }

      it "returns true" do
        expect(script.evaluate(0x1111)).to be true
      end
    end

    context "when the script matches the p2sh pattern" do
      let(:redeem_script) { "" }
      let(:redeem_script_hash160) { HashHelper.hash160(redeem_script) }
      let(:commands) do
        [
          redeem_script,
          169,
          redeem_script_hash160,
          135
        ]
      end

      context "when the script finishes with a nonzero top element" do
        let(:redeem_script) { "\x51" }

        it "returns true" do
          expect(script.evaluate(0x1111)).to be true
        end
      end

      context "when the script finishes with an empty string as top element" do
        let(:redeem_script) { "\x00" }

        it "returns false" do
          expect(script.evaluate(0x1111)).to be false
        end
      end

      context "when the script hash does not match the given hash160" do
        let(:redeem_script) { "\x51" }
        let(:redeem_script_hash160) { HashHelper.hash160("\x01") }

        it "returns false" do
          expect(script.evaluate(0x1111)).to be false
        end
      end
    end
  end

  describe '#p2sh?' do
    let!(:script) { described_class.new(commands) }
    let(:commands) { [] }

    context "when the script matches the p2sh pattern" do
      let(:redeem_script_hash160) { HashHelper.hash160('') }
      let(:commands) do
        [
          169,
          redeem_script_hash160,
          135
        ]
      end
      let!(:script) { described_class.new(commands) }

      it 'returns true' do
        expect(script.p2sh?).to be true
      end
    end

    context "when the script does not match the p2sh pattern" do
      let(:commands) do
        [
          '',
          18,
          135
        ]
      end
      let!(:script) { described_class.new(commands) }

      it 'returns false' do
        expect(script.p2sh?).to be false
      end
    end
  end

  describe '#p2wpkh?' do
    let!(:script) { described_class.new(commands) }
    let(:commands) { [] }

    context "when the script matches the p2wpkh pattern" do
      let(:hash160) { HashHelper.hash160('') }
      let(:commands) do
        [
          0,
          hash160
        ]
      end
      let!(:script) { described_class.new(commands) }

      it 'returns true' do
        expect(script.p2wpkh?).to be true
      end
    end

    context "when the script does not match the p2wpkh pattern" do
      let(:commands) do
        [
          '',
          18,
          135
        ]
      end
      let!(:script) { described_class.new(commands) }

      it 'returns false' do
        expect(script.p2wpkh?).to be false
      end
    end
  end

  describe '#p2wsh?' do
    let!(:script) { described_class.new(commands) }
    let(:commands) { [] }

    context "when the script matches the p2wsh pattern" do
      let(:hash256) { HashHelper.hash256('') }
      let(:commands) do
        [
          0,
          hash256
        ]
      end
      let!(:script) { described_class.new(commands) }

      it 'returns true' do
        expect(script.p2wsh?).to be true
      end
    end

    context "when the script does not match the p2wsh pattern" do
      let(:commands) do
        [
          '',
          18
        ]
      end
      let!(:script) { described_class.new(commands) }

      it 'returns false' do
        expect(script.p2wsh?).to be false
      end
    end
  end

  describe "#+" do
    it "adds the commands arrays" do
      script1 = described_class.new([1, 2])
      script2 = described_class.new([3, 4])

      expect(script1 + script2).to eq(described_class.new([1, 2, 3, 4]))
    end
  end
end

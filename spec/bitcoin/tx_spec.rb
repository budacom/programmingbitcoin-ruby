require 'bitcoin/tx'
require 'bitcoin/script'
require 'encoding_helper'
require_relative '../support/fixture_macros'
require_relative '../../lib/ecc/private_key'
require 'pry'

RSpec.describe Bitcoin::Tx do
  load_transaction_set 'transactions'
  include EncodingHelper

  let(:raw_tx) { resolve_tx '452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03' }
  let(:raw_tx_sw) { resolve_tx '9b4fc533a9a69ed0eb030b08e40150999a8aa871e918345cb19855298c103ba3' }

  describe ".parse" do
    def parse(*_args)
      described_class.parse(*_args)
    end

    context 'when tx is legacy' do
      it "properly parses the version" do
        expect(parse(raw_tx).version).to eq(1)
      end

      it "properly parses input count" do
        expect(parse(raw_tx).ins.count).to eq(1)
      end

      it "properly parses each input prev_tx" do
        expect(bytes_to_hex(parse(raw_tx).ins.first.prev_tx)).to eq "d1c789a9c60383bf715f3f6ad9d14b91\
fe55f3deb369fe5d9280cb1a01793f81"
      end

      it "properly parses each input prev_index" do
        expect(parse(raw_tx).ins.first.prev_index).to eq 0
      end

      it "properly parses each input script_sig" do
        expect(bytes_to_hex(parse(raw_tx).ins.first.script_sig.serialize))
          .to eq "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320\
b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c3\
1967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a"
      end

      it "properly parses each input sequence" do
        expect(parse(raw_tx).ins.first.sequence).to eq 0xfffffffe
      end

      it "properly parses output count" do
        expect(parse(raw_tx).outs.count).to eq(2)
      end

      it "properly parses each output amount" do
        expect(parse(raw_tx).outs.map(&:amount)).to eq([32454049, 10011545])
      end

      it "properly parses each output script_pubkey" do
        expect(parse(raw_tx).outs.map { |o| bytes_to_hex(o.script_pubkey.serialize) }).to eq(
          [
            '1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac',
            '1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac'
          ]
        )
      end
    end

    context 'when tx is segwit' do
      it "properly parses the version" do
        expect(parse(raw_tx_sw).version).to eq(2)
      end

      it "properly parses input count" do
        expect(parse(raw_tx_sw).ins.count).to eq(1)
      end

      it "properly parses each input prev_tx" do
        expect(bytes_to_hex(parse(raw_tx_sw).ins.first.prev_tx))
          .to eq "2cbe83a5efe4d6582eb8f5a029c65f74832c734c89234081a25ad3f997ba74e8"
      end

      it "properly parses each input prev_index" do
        expect(parse(raw_tx_sw).ins.first.prev_index).to eq 0
      end

      it "properly parses each input script_sig" do
        expect(parse(raw_tx_sw).ins.first.script_sig.serialize).to eq "\x00"
      end

      it "properly parses each input sequence" do
        expect(parse(raw_tx_sw).ins.first.sequence).to eq 0xffffffff
      end

      it "properly parses output count" do
        expect(parse(raw_tx_sw).outs.count).to eq(2)
      end

      it "properly parses each output amount" do
        expect(parse(raw_tx_sw).outs.map(&:amount)).to eq([176500, 2178124])
      end

      it "properly parses each output script_pubkey" do
        skip
        # todo : check correct script_pub. should be : [76a91433e73d0a40a60d02d19c8b8d38ad6da14306683b88ac, 001424ca8b17be9dfa365929dc9251da7d1533ca8b5e]
        expect(parse(raw_tx_sw).outs.map { |o| bytes_to_hex(o.script_pubkey.serialize) }).to eq(
          [
            '1976a91433e73d0a40a60d02d19c8b8d38ad6da14306683b88ac',
            '16001424ca8b17be9dfa365929dc9251da7d1533ca8b5e'
          ]
        )
      end

      it "properly parses each input witness" do
        witness = parse(raw_tx_sw).ins.first.witness.map { |w| w.unpack1("H*") }

        expect(witness).to eq(
          [
            "30440220635a9629c9eb17f7ebbfc200e674aff253ec4213c3e6d3207e86886af9f6a75"\
            "1022072e2d54a9b8079e37cefd856ccf3c2383858346f55197d32c3a7fad18eac48e001",
            "02550e51f143d27ed811e8cdf9008a21211bf26c73866a4b077117496b432421bd"
          ]
        )
      end
    end
  end

  describe "#fee" do
    let(:tx) { described_class.parse raw_tx, tx_fetcher: tx_fetcher }

    it "returns the result of substracting the input amount from the output amount" do
      expect(tx.fee).to eq 40000
    end

    context "when transaction has more than one input" do
      let(:raw_tx) do
        hex_to_byte_stream(
          "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a4730\
4402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f71\
00ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e\
253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a4730440\
2207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b\
23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c\
15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a4730440220\
4c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34\
210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58a\
ce5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a4730440220063\
3ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751\
635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d5\
5feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976\
a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600"
        )
      end

      it "returns the correct fee" do
        expect(tx.fee).to eq 140500
      end
    end
  end

  def hex_to_byte_stream(_str)
    StringIO.new([_str].pack("H*"))
  end

  def bytes_to_hex(_bytes)
    _bytes.unpack1("H*")
  end

  describe '#sig_hash' do
    let(:tx) { described_class.parse raw_tx, tx_fetcher: tx_fetcher }
    let(:raw_tx) do
      hex_to_byte_stream(
        "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045\
022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d\
3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213\
bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000\
000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
      )
    end

    it 'returns the correct sig_hash' do
      expect(tx.sig_hash(0))
        .to eq 18037338614366229343027734445863508930887653120159589908930024158807354868134
    end
  end

  describe '#sig_hash_bip143' do
    context 'when tx is segwit' do
      let(:tx_sw) { described_class.parse raw_tx_sw, tx_fetcher: tx_fetcher }

      it 'returns the correct sig_hash' do
        skip
        # todo: give correct witness as input

        cmd = tx_sw.ins.first.witness.last
        raw_witness = encode_varint(cmd.size) + cmd
        witness_script = Bitcoin::Script.parse(StringIO.new(raw_witness))

        expect(tx_sw.sig_hash_bip143(0, witness_script: witness_script))
          .to eq 999999
      end
    end
  end

  describe '#verify_input' do
    let(:tx) { described_class.parse raw_tx, tx_fetcher: tx_fetcher }
    let(:raw_tx) do
      hex_to_byte_stream(
        "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045\
022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d\
3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213\
bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000\
000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
      )
    end

    it 'verifies unlocking script unlocks the script' do
      expect(tx.verify_input(0)).to be true
    end

    context 'when the script pubkey is p2sh' do
      let(:raw_tx) do
        resolve_tx '46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b'
      end

      it 'verifies unlocking script unlocks the script' do
        expect(tx.verify_input(0)).to be true
      end
    end

    context 'when tx is segwit and the script pubkey is p2wpkh' do
      let(:tx_p2wpkh) { described_class.parse raw_tx_sw, tx_fetcher: tx_fetcher }

      it 'verifies unlocking script unlocks the script' do
        skip
        expect(tx_p2wpkh.verify_input(0)).to be true
      end
    end

    context 'when tx is segwit and the script pubkey is p2wsh' do
      let(:raw_tx_p2wsh) do
        resolve_tx '98abf6f18cedc5e527775ff2b0d4235b16fd40774c33ab7c599e20099fd11259'
      end
      let(:tx_p2wsh) { described_class.parse raw_tx_p2wsh, tx_fetcher: tx_fetcher }

      it 'verifies unlocking script unlocks the script' do
        skip
        expect(tx_p2wsh.verify_input(0)).to be true
      end
    end
  end

  describe '#sign_input' do
    let(:tx) { described_class.parse raw_tx, tx_fetcher: tx_fetcher, testnet: true }
    let(:raw_tx) do
      hex_to_byte_stream(
        "010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffffff\
ff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507\
b27411ccf7f16f10297de6cef3f291623eddf88ac00000000"
      )
    end
    let(:private_key) { ECC::PrivateKey.new(8675309) }

    it 'signs the input' do
      expect(tx.sign_input(0, private_key)).to be true
    end
  end

  describe '#coinbase?' do
    let(:tx) { described_class.parse raw_tx }

    context 'when tx is coinbase' do
      let(:raw_tx) do
        hex_to_byte_stream(
          "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d7\
1b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34a\
fc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf2\
0b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000"
        )
      end

      it { expect(tx.coinbase?).to be true }
    end

    context 'when tx is not coinbase' do
      let(:raw_tx) do
        hex_to_byte_stream(
          "010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffff\
ffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a9145\
07b27411ccf7f16f10297de6cef3f291623eddf88ac00000000"
        )
      end

      it { expect(tx.coinbase?).to be false }
    end
  end

  describe '#coinbase_height' do
    let(:tx) { described_class.parse raw_tx }

    context 'when tx is not coinbase' do
      let(:raw_tx) do
        hex_to_byte_stream(
          "010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffff\
ffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a9145\
07b27411ccf7f16f10297de6cef3f291623eddf88ac00000000"
        )
      end

      it { expect(tx.coinbase_height).to be nil }
    end

    context 'when tx is coinbase' do
      let(:raw_tx) do
        hex_to_byte_stream(
          "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d7\
1b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34a\
fc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf2\
0b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000"
        )
      end

      it 'returns the block height' do
        expect(tx.coinbase_height).to be 465879
      end
    end
  end

  describe '#segwit?' do
    context 'when tx is legacy' do
      it 'returns false' do
        expect(described_class.segwit?(raw_tx)).to be false
      end
    end

    context 'when tx is segwit' do
      it 'returns true' do
        expect(described_class.segwit?(raw_tx_sw)).to be true
      end
    end
  end

  describe '#serialize' do
    let(:tx) { described_class.parse raw_tx, tx_fetcher: tx_fetcher }

    context 'when tx is legacy' do
      it 'returns serialized tx' do
        expect(bytes_to_hex(tx.serialize)).to eq(
          "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b48"\
          "3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d95"\
          "5c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f"\
          "5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56"\
          "b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40d"\
          "f79fea1288ac19430600"
        )
      end
    end

    context 'when tx is segwit' do
      let(:tx_sw) { described_class.parse raw_tx_sw, tx_fetcher: tx_fetcher }

      it 'returns serialized tx' do
        expect(bytes_to_hex(tx_sw.serialize)).to eq(
          "02000000000101e874ba97f9d35aa2814023894c732c83745fc629a0f5b82e58d6e4efa583be2c"\
          "0000000000ffffffff0274b10200000000001976a91433e73d0a40a60d02d19c8b8d38ad6da1430"\
          "6683b88ac4c3c21000000000016001424ca8b17be9dfa365929dc9251da7d1533ca8b5e024730440"\
          "220635a9629c9eb17f7ebbfc200e674aff253ec4213c3e6d3207e86886af9f6a751022072e2d54a9"\
          "b8079e37cefd856ccf3c2383858346f55197d32c3a7fad18eac48e0012102550e51f143d27ed811e8"\
          "cdf9008a21211bf26c73866a4b077117496b432421bd00000000"
        )
      end
    end
  end
end

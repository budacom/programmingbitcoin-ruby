require 'bitcoin/tx'
require_relative '../support/fixture_macros'

RSpec.describe Bitcoin::Tx do
  load_transaction_set 'transactions'

  let(:raw_tx) { resolve_tx '452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03' }

  describe ".parse" do
    def parse(*_args)
      described_class.parse(*_args)
    end

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
      expect(bytes_to_hex(parse(raw_tx).ins.first.script_sig)).to eq "483045022100ed81ff192e75a\
3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c3\
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
      expect(parse(raw_tx).outs.map { |o| bytes_to_hex(o.raw_script_pubkey) }).to eq(
        [
          '76a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac',
          '76a9141c4bc762dd5423e332166702cb75f40df79fea1288ac'
        ]
      )
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
    # TODO: Completar
    let(:raw_tx) {}

    it 'returns the correct sig_hash' do
      # TODO: Completar
      expect(tx.sig_hash(0)).to eq ''
    end
  end

  describe '#verify_input' do
    let(:tx) { described_class.parse raw_tx, tx_fetcher: tx_fetcher }
     # TODO: Completar
    let(:raw_tx) {}

    it 'verifies the input' do
      # TODO: Completar
      expect(tx.verify_input(0)).to eq ''
    end
  end

  describe '#sign_input' do
    let(:tx) { described_class.parse raw_tx, tx_fetcher: tx_fetcher }
     # TODO: Completar
    let(:raw_tx) {}
    let(:private_key) {}

    it 'signs the input' do
      # TODO: Completar
      expect(tx.sign_input(0, private_key)).to eq ''
    end
  end
end

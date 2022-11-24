# encoding: ascii-8bit

require 'bitcoin/network/envelope'
require 'helpers/encoding_helper'

RSpec.describe Bitcoin::Network::Envelope do
  include EncodingHelper

  let(:raw_envelope) { from_hex_to_bytes("f9beb4d976657261636b000000000000000000005df6e0e2") }

  def parse(_raw_envelope)
    described_class.parse(StringIO.new(_raw_envelope))
  end

  describe '.parse' do
    it 'properly parses magic hex' do
      expect(parse(raw_envelope).magic_hex).to eq Bitcoin::Network::Envelope::NETWORK_MAGIC
    end

    it 'properly parses command bytes' do
      expect(parse(raw_envelope).command_bytes).to eq "verack"
    end

    it 'properly parses payload bytes' do
      expect(parse(raw_envelope).payload_bytes).to eq ""
    end
  end

  describe "#to_s" do
    it "returns a string containing the command and the payload" do
      expect(parse(raw_envelope).to_s).to(eq("verack: "))
    end
  end

  describe "#serialize" do
    it "serializes correctly" do
      envelope = described_class.new("ping", "\x00\x00\x00\x00\x00\x00\x00\x01", "f9beb4d9")

      expect(envelope.serialize).to(
        eq(
          "\v\x11\t\aping\x00\x00\x00\x00\x00\x00\x00\x00\b\x00\x00\x00:\xE5\xC1\x98\x00\x00\x00\x00\x00\x00\x00\x01"
        )
      )
    end

    it "serializes same envelope" do
      expect(parse(raw_envelope).serialize).to(eq(raw_envelope))
    end
  end
end

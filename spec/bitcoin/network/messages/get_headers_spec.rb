require 'bitcoin/network/messages/get_headers'
require 'bitcoin/block'
require 'helpers/encoding_helper'

RSpec.describe Bitcoin::Network::Messages::GetHeaders do
  include EncodingHelper

  def serialized_message_hex
    bytes_to_hex(described_class.new(start_block: Bitcoin::Block::TESTNET_GENESIS_BLOCK).serialize)
  end

  describe "#serialize" do
    it "serializes version" do
      expect(serialized_message_hex.slice(0, 8)).to(eq("7f110100"))
    end

    it "serializes num_hashes" do
      expect(serialized_message_hex.slice(8, 2)).to(eq("01"))
    end

    it "serializes start_block" do
      expect(serialized_message_hex.slice(10, 160))
        .to(eq(bytes_to_hex(Bitcoin::Block::TESTNET_GENESIS_BLOCK.reverse)))
    end

    it "serializes end_block" do
      expect(serialized_message_hex.slice(170, 16)).to(eq("0000000000000000"))
    end
  end
end

require 'bitcoin/network/messages/get_data'
require 'helpers/encoding_helper'

RSpec.describe Bitcoin::Network::Messages::GetData do
  include EncodingHelper

  def serialized_message_hex
    get_data = described_class.new
    block1 = from_hex_to_bytes('00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30')
    get_data.add_data(data_type: described_class::FILTERED_BLOCK_DATA_TYPE, identifier: block1)
    block2 = from_hex_to_bytes('00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910')
    get_data.add_data(data_type: described_class::FILTERED_BLOCK_DATA_TYPE, identifier: block2)
    bytes_to_hex(get_data.serialize)
  end

  describe "#serialize" do
    it "serializes version" do
      expected_hex = "020300000030eb2540c41025690160a1014c577061596e32e426b712c7ca000000000000000\
30000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000"
      expect(serialized_message_hex).to eq expected_hex
    end
  end
end

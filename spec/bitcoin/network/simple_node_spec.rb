# encoding: ascii-8bit

require 'bitcoin/network/simple_node'
require 'helpers/encoding_helper'

RSpec.describe Bitcoin::Network::SimpleNode do
  include EncodingHelper

  describe '#wait_for' do
    let(:socket) { instance_double(Socket) }

    let(:envelope_verack) { instance_double(Bitcoin::Network::Envelope) }
    let(:envelope_another_msg) { instance_double(Bitcoin::Network::Envelope) }

    let(:verack_instance) { instance_double(Bitcoin::Network::Messages::Verack) }

    before do
      allow(Socket).to receive(:new).and_return(socket)
      allow(Socket).to receive(:pack_sockaddr_in)
      allow(socket).to receive(:connect)

      allow(envelope_verack).to receive(:command_bytes).and_return('verack')
      allow(envelope_another_msg).to receive(:command_bytes).and_return('another_msg')

      allow(Bitcoin::Network::Envelope).to receive(:parse).and_return(
        envelope_another_msg,
        envelope_verack
      )

      allow(envelope_verack).to receive(:stream).and_return('stream')

      allow(Bitcoin::Network::Messages::Verack).to receive(:parse).and_return(verack_instance)
    end

    it 'loops while the searched message is read' do
      message_class = Bitcoin::Network::Messages::Verack

      instance = described_class.new('host', 1111)
      instance.wait_for(message_class)

      expect(Bitcoin::Network::Envelope).to have_received(:parse).exactly(2).times
    end

    it 'returns the parsed message class' do
      message_class = Bitcoin::Network::Messages::Verack

      instance = described_class.new('host', 1111)
      result = instance.wait_for(message_class)

      expect(result).to eq(verack_instance)
    end
  end
end

require_relative './fetcher'
require_relative '../tx'
require_relative '../../helpers/encoding_helper'
require 'net/http'
require 'stringio'

class UriFetcher < Fetcher
  include EncodingHelper

  def fetch(tx_id, testnet: false)
    url = URI("#{base_url(testnet: testnet)}/tx/#{tx_id}/hex")
    res = Net::HTTP.get(url)
    raw = from_hex_to_bytes(res)
    if raw[4] == "\x00"
      raw = raw[...4] + raw[6...]
      tx = Bitcoin::Tx.parse(StringIO.new(raw), testnet: testnet)
      tx.locktime = from_bytes(raw[-4...], 'little')
    else
      tx = Bitcoin::Tx.parse(StringIO.new(raw), testnet: testnet)
    end

    raise "not the same id: #{tx.id.first} vs #{tx_id}" if tx.id.first != tx_id

    tx
  end

  private

  def base_url(testnet: false)
    testnet ? 'https://blockstream.info/testnet/api' : 'https://blockstream.info/api'
  end
end

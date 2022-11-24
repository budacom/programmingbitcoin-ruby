# encoding: ascii-8bit

require_relative 'encoding_helper'

module AddressHelper
  include EncodingHelper
  extend self

  def h160_to_p2pkh_address(h160, testnet: false)
    prefix = testnet ? "\x6f" : "\x00"

    encode_base58_checksum(prefix + h160)
  end

  def h160_to_p2sh_address(h160, testnet: false)
    prefix = testnet ? "\xc4" : "\x05"

    encode_base58_checksum(prefix + h160)
  end
end

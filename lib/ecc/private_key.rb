require_relative 's256_point'
require_relative 'signature'
require_relative 'secp256k1_constants'
require_relative '../helpers/encoding_helper'
require 'openssl'

module ECC
  class PrivateKey
    include EncodingHelper
    attr_reader :point

    def initialize(secret)
      @secret = secret
      @point = secret * ECC::S256Point::G
    end

    def to_s
      @num.to_s.rjust(64, '0')
    end

    def sign(z)
      k = deterministic_k(z)
      r = (k * ECC::S256Point::G).x.num
      k_inv = k.pow(Secp256k1Constants::N - 2, Secp256k1Constants::N)
      s = (z + r * @secret) * k_inv % Secp256k1Constants::N

      s = Secp256k1Constants::N - s if s > Secp256k1Constants::N / 2

      ECC::Signature.new(r, s)
    end

    def wif(compressed: true, testnet: false)
      secret_bytes = to_bytes(@secret, 32, 'big')
      prefix = to_bytes(testnet ? 0xef : 0x80, 1, 'big')
      suffix = compressed ? "\x01" : ""
      encode_base58_checksum("#{prefix}#{secret_bytes}#{suffix}")
    end

    private

    def deterministic_k(z)
      z -= Secp256k1Constants::N if z > Secp256k1Constants::N

      z_bytes = to_bytes(z, 32, 'big')
      secret_bytes = to_bytes(@secret, 32, 'big')

      k = sha256_hmac("\x00" * 32, "#{"\x01" * 32}\x00#{secret_bytes}#{z_bytes}")
      v = sha256_hmac(k, "\x01" * 32)

      k = sha256_hmac(k, "#{v}\x01#{secret_bytes}#{z_bytes}")
      v = sha256_hmac(k, v)

      loop do
        v = sha256_hmac(k, v)
        candidate = from_bytes(v, 'big')
        return candidate if candidate >= 1 && candidate < Secp256k1Constants::N

        k = sha256_hmac(k, "#{v}\x00")
        v = sha256_hmac(k, v)
      end
    end

    def sha256_hmac(key, data)
      OpenSSL::HMAC.digest("SHA256", key, data)
    end
  end
end

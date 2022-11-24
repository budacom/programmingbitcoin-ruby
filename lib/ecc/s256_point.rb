require_relative 's256_field'
require_relative 'point'
require_relative 'secp256k1_constants'
require_relative '../helpers/encoding_helper'
require_relative '../helpers/hash_helper'
require_relative '../helpers/address_helper'
module ECC
  class S256Point < Point
    include EncodingHelper
    extend EncodingHelper

    def initialize(x, y, _a = 0, _b = 7)
      a = S256Field.new(Secp256k1Constants::A)
      b = S256Field.new(Secp256k1Constants::B)

      if x.is_a?(Integer)
        x = S256Field.new(x)
        y = S256Field.new(y)
      end

      super(x, y, a, b)
    end

    G = S256Point.new(Secp256k1Constants::G_X, Secp256k1Constants::G_Y)

    def to_s
      return "Point(infinity)_S256Field" if @x.nil? && @y.nil?

      "Point(#{@x}, #{@y})_S256Field"
    end

    def *(coef)
      coef = coef % Secp256k1Constants::N
      super(coef)
    end

    def verify(z, signature)
      s_inv = signature.s.pow(Secp256k1Constants::N - 2, Secp256k1Constants::N)
      u = z * s_inv % Secp256k1Constants::N
      v = signature.r * s_inv % Secp256k1Constants::N
      random_target = (u * self.class::G + v * self).x.num
      random_target == signature.r
    end

    def sec(compressed: true)
      if compressed
        prefix = y.num.even? ? to_bytes(2, 1, 'big') : to_bytes(3, 1, 'big')
        return prefix + to_bytes(x.num, 32, 'big')
      end

      to_bytes(4, 1, 'big') + to_bytes(x.num, 32, 'big') + to_bytes(y.num, 32, 'big')
    end

    def hash160(compressed: true)
      HashHelper.hash160(sec(compressed: compressed))
    end

    def address(compressed: true, testnet: false)
      AddressHelper.h160_to_p2pkh_address(
        hash160(compressed: compressed),
        testnet: testnet
      )
    end

    def self.parse(sec_bin)
      return parse_uncompressed(sec_bin) if sec_bin[0] == "\x04"

      x = S256Field.new(from_bytes(sec_bin[1..], 'big'))
      alpha = x**3 + S256Field.new(Secp256k1Constants::B)
      beta = alpha.sqrt
      if beta.num.even?
        even_beta = beta
        odd_beta = S256Field.new(Secp256k1Constants::P - beta.num)
      else
        even_beta = S256Field.new(Secp256k1Constants::P - beta.num)
        odd_beta = beta
      end
      sec_bin[0] == "\x02" ? new(x, even_beta) : new(x, odd_beta)
    end

    def self.parse_uncompressed(sec_bin)
      x = from_bytes(sec_bin.slice(1, 32), 'big')
      y = from_bytes(sec_bin.slice(33, 32), 'big')
      new(x, y)
    end

    private_class_method :parse_uncompressed
  end
end

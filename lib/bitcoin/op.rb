require_relative '../helpers/hash_helper'
require_relative '../helpers/encoding_helper'
require_relative '../helpers/script_helper'
require_relative '../ecc/signature'
require_relative '../ecc/s256_point'

module Bitcoin
  module Op # rubocop:disable Metrics/ModuleLength
    include EncodingHelper
    include ScriptHelper

    (0..16).each do |num|
      define_method :"op_#{num}" do |stack|
        stack << encode_num(num)
        true
      end
    end

    def op_drop(stack)
      return false if stack.empty?

      stack.pop
      true
    end

    def op_dup(stack)
      return false if stack.empty?

      stack << stack.last
      true
    end

    def op_hash160(stack)
      return false if stack.empty?

      element = stack.pop
      stack << HashHelper.hash160(element)
      true
    end

    def op_hash256(stack)
      return false if stack.empty?

      element = stack.pop
      stack << HashHelper.hash256(element)
      true
    end

    def op_checksig(stack, z) # rubocop:disable Naming/MethodParameterName
      return false if stack.length < 2

      sec_pubkey = stack.pop
      der_signature = stack.pop.chop

      begin
        point = ECC::S256Point.parse(sec_pubkey)
        sig = ECC::Signature.parse(der_signature)
      rescue TypeError, ECC::SignatureError
        return false
      end

      stack << (point.verify(z, sig) ? encode_num(1) : encode_num(0))
      true
    end

    def op_verify(stack)
      return false if stack.empty?

      element = stack.pop

      !decode_num(element).zero?
    end

    def op_equal(stack)
      return false if stack.length < 2

      element1 = stack.pop
      element2 = stack.pop

      num = element1 == element2 ? encode_num(1) : encode_num(0)
      stack.append num

      true
    end

    def op_equalverify(stack)
      op_equal(stack) && op_verify(stack)
    end

    def op_checkmultisig(stack, z) # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/MethodParameterName
      return false if stack.empty?

      n = decode_num(stack.pop)
      return false if stack.length < n + 1

      sec_pubkeys = []
      n.times { sec_pubkeys << stack.pop }

      m = decode_num(stack.pop)
      return false if stack.length < m + 1

      der_signatures = []
      m.times { der_signatures << stack.pop[0...-1] }

      stack.pop

      begin
        points = sec_pubkeys.map { |sec| ECC::S256Point.parse(sec) }
        sigs = der_signatures.map { |der| ECC::Signature.parse(der) }

        sigs_to_verify = m
        sigs.each do |sig|
          return false if points.empty?

          while points.any?
            point = points.shift
            if point.verify(z, sig)
              sigs_to_verify -= 1
              break
            end
          end
          return false if sigs_to_verify > points.length
        end

        stack.append(encode_num(1))
      rescue SyntaxError, ECC::SignatureError
        return false
      end

      true
    end

    OP_CODE_NAMES = {
      0 => 'OP_0',
      76 => 'OP_PUSHDATA1',
      77 => 'OP_PUSHDATA2',
      78 => 'OP_PUSHDATA4',
      79 => 'OP_1NEGATE',
      81 => 'OP_1',
      82 => 'OP_2',
      83 => 'OP_3',
      84 => 'OP_4',
      85 => 'OP_5',
      86 => 'OP_6',
      87 => 'OP_7',
      88 => 'OP_8',
      89 => 'OP_9',
      90 => 'OP_10',
      91 => 'OP_11',
      92 => 'OP_12',
      93 => 'OP_13',
      94 => 'OP_14',
      95 => 'OP_15',
      96 => 'OP_16',
      97 => 'OP_NOP',
      99 => 'OP_IF',
      100 => 'OP_NOTIF',
      103 => 'OP_ELSE',
      104 => 'OP_ENDIF',
      105 => 'OP_VERIFY',
      106 => 'OP_RETURN',
      107 => 'OP_TOALTSTACK',
      108 => 'OP_FROMALTSTACK',
      109 => 'OP_2DROP',
      110 => 'OP_2DUP',
      111 => 'OP_3DUP',
      112 => 'OP_2OVER',
      113 => 'OP_2ROT',
      114 => 'OP_2SWAP',
      115 => 'OP_IFDUP',
      116 => 'OP_DEPTH',
      117 => 'OP_DROP',
      118 => 'OP_DUP',
      119 => 'OP_NIP',
      120 => 'OP_OVER',
      121 => 'OP_PICK',
      122 => 'OP_ROLL',
      123 => 'OP_ROT',
      124 => 'OP_SWAP',
      125 => 'OP_TUCK',
      130 => 'OP_SIZE',
      135 => 'OP_EQUAL',
      136 => 'OP_EQUALVERIFY',
      139 => 'OP_1ADD',
      140 => 'OP_1SUB',
      143 => 'OP_NEGATE',
      144 => 'OP_ABS',
      145 => 'OP_NOT',
      146 => 'OP_0NOTEQUAL',
      147 => 'OP_ADD',
      148 => 'OP_SUB',
      149 => 'OP_MUL',
      154 => 'OP_BOOLAND',
      155 => 'OP_BOOLOR',
      156 => 'OP_NUMEQUAL',
      157 => 'OP_NUMEQUALVERIFY',
      158 => 'OP_NUMNOTEQUAL',
      159 => 'OP_LESSTHAN',
      160 => 'OP_GREATERTHAN',
      161 => 'OP_LESSTHANOREQUAL',
      162 => 'OP_GREATERTHANOREQUAL',
      163 => 'OP_MIN',
      164 => 'OP_MAX',
      165 => 'OP_WITHIN',
      166 => 'OP_RIPEMD160',
      167 => 'OP_SHA1',
      168 => 'OP_SHA256',
      169 => 'OP_HASH160',
      170 => 'OP_HASH256',
      171 => 'OP_CODESEPARATOR',
      172 => 'OP_CHECKSIG',
      173 => 'OP_CHECKSIGVERIFY',
      174 => 'OP_CHECKMULTISIG',
      175 => 'OP_CHECKMULTISIGVERIFY',
      176 => 'OP_NOP1',
      177 => 'OP_CHECKLOCKTIMEVERIFY',
      178 => 'OP_CHECKSEQUENCEVERIFY',
      179 => 'OP_NOP4',
      180 => 'OP_NOP5',
      181 => 'OP_NOP6',
      182 => 'OP_NOP7',
      183 => 'OP_NOP8',
      184 => 'OP_NOP9',
      185 => 'OP_NOP10'
    }
  end
end

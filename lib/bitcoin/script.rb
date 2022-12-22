require_relative '../bitcoin_data_io'
require_relative '../encoding_helper'
require_relative '../hash_helper'
require_relative './op'

module Bitcoin
  class Script
    include Bitcoin::Op
    include EncodingHelper
    extend EncodingHelper

    attr_reader :cmds

    OP_CODE_FUNCTIONS = Hash[*instance_methods.grep(/^op_/).map do |m|
      [ (OP_CODE_NAMES.find{|_, v| v == m.to_s.upcase }.first rescue nil), m]
    end.flatten]

    def initialize(cmds = nil)
      @cmds = cmds || []
    end

    def to_s
      result = []
      @cmds.each do |cmd|
        if cmd.is_a? Integer
          name = OP_CODE_NAMES[cmd] || "OP_[#{cmd}]"
          result.append(name)
        else
          result.append(cmd.unpack1('H*'))
        end
      end

      result.join(' ')
    end

    def +(other)
      self.class.new(@cmds + other.cmds)
    end

    def ==(other)
      @cmds == other.cmds
    end

    def self.parse(_io)
      io = BitcoinDataIO(_io)

      length = io.read_varint
      cmds = []
      count = 0

      while count < length
        current_byte = io.read(1).unpack1('C')
        cmd_bytes = parse_command(current_byte, io, cmds)
        count += 1 + cmd_bytes
      end

      raise SyntaxError.new('parsing script failed') if count != length

      new(cmds)
    end

    def self.parse_command(current_byte, io, cmds) # rubocop:disable Metrics/MethodLength
      case current_byte
      when 1..75
        n = current_byte
        cmds.append(io.read(n))
        n

      when 76
        data_length = little_endian_to_int(io.read(1))
        cmds.append(io.read(data_length))
        data_length + 1

      when 77
        data_length = little_endian_to_int(io.read(2))
        cmds.append(io.read(data_length))
        data_length + 2

      else
        op_code = current_byte
        cmds.append(op_code)
        0
      end
    end

    def serialize
      raw = raw_serialize

      encode_varint(raw.length) + raw
    end

    def evaluate(z, witness: nil)
      cmds = @cmds.clone
      stack = []
      altstack = []

      while cmds.any?
        cmd = cmds.shift
        return false unless resolve_cmd(cmd, cmds, stack, altstack, z, witness: witness)
      end

      return false if stack.empty? || stack.pop.empty?

      true
    end

    def p2sh?(cmds = @cmds)
      cmds.length == 3 \
      && cmds[0] == 169 \
      && cmds[1].is_a?(String) && cmds[1].length == 20 \
      && cmds[2] == 135
    end

    def p2wpkh?(cmds = @cmds)
      cmds.length == 2 \
      && cmds[0] == 0 \
      && cmds[1].is_a?(String) && cmds[1].length == 20
    end

    def p2wsh?(cmds = @cmds)
      cmds.length == 2 \
      && cmds[0] == 0 \
      && cmds[1].is_a?(String) && cmds[1].length == 32
    end

    def self.p2pkh(hash160)
      Script.new([118, 169, hash160, 136, 172])
    end

    def self.p2wpkh(hash160)
      Script.new([0, hash160])
    end

    def self.p2wsh(hash256)
      Script.new([0, hash256])
    end

    private

    def resolve_cmd(cmd, cmds, stack, altstack, z, witness: nil)
      if cmd.is_a? Integer
        return execute_operation(cmd, cmds, stack, altstack, z)
      else
        stack.append(cmd)

        if p2sh?(cmds)
          return execute_p2sh(cmd, cmds, stack)
        elsif p2wpkh?
          return execute_p2wpkh(cmds, stack, witness)
        elsif p2wsh?
          return execute_p2wsh(cmds, stack, witness)
        end
      end

      true
    end

    def execute_p2sh(cmd, cmds, stack)
      cmds.pop
      h160 = cmds.pop
      cmds.pop

      return false unless op_hash160(stack)

      stack.append(h160)
      return false unless op_equal(stack)
      return false unless op_verify(stack)

      redeem_script = encode_varint(cmd.length) + cmd
      stream = StringIO.new(redeem_script)
      cmds.concat self.class.parse(stream).cmds
    end

    def execute_p2wpkh(cmds, stack, witness)
      h160 = stack.pop
      stack.pop
      cmds.concat witness
      cmds.concat self.class.p2wpkh(h160).cmds
    end

    def execute_p2wsh(cmds, stack, witness)
      s256_stack = stack.pop
      stack.pop
      cmds.concat witness[0...-1]
      witness_script = witness.last
      s256_script = HashHelper.hash256(witness_script)

      unless s256_stack == s256_script
        raise "Witness script hash mismatch: \n"\
          "stack: #{bytes_to_hex(s256_stack)} \n"\
          "script: #{bytes_to_hex(s256_script)}"
      end

      stream = encode_varint(witness_script.size) + witness_script
      cmds.concat parse(stream).cmds
    end

    def raw_serialize
      @cmds.map do |cmd|
        cmd.is_a?(Integer) ? int_to_little_endian(cmd, 1) : serialized_element_prefix(cmd) + cmd
      end.join
    end

    def serialized_element_prefix(cmd)
      length = cmd.length
      case length
      when 0..75
        int_to_little_endian(length, 1)
      when 76..255 # OP_PUSHDATA1 + length (1 byte)
        int_to_little_endian(76, 1) + int_to_little_endian(length, 1)
      when 256..520 # OP_PUSHDATA2 + length (2 bytes)
        int_to_little_endian(77, 1) + int_to_little_endian(length, 2)
      else
        raise TypeError.new('too long an cmd')
      end
    end

    def op_code_function(op_code)
      function = OP_CODE_FUNCTIONS[op_code]
      unless function
        raise NotImplementedError.new(
          "operation #{OP_CODE_NAMES[op_code] || op_code} not implemented"
        )
      end

      method(function)
    end

    def execute_operation(op_code, cmds, stack, altstack, z)
      operation = op_code_function(op_code)

      case op_code
      when 99, 100
        operation.call(stack, cmds)

      when 107, 108
        operation.call(stack, altstack)

      when 172, 173, 174, 175
        operation.call(stack, z)

      else
        operation.call(stack)
      end
    end

    private_class_method :parse_command
  end
end

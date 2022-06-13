require_relative '../bitcoin_data_io'
require_relative '../encoding_helper'
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

    def evaluate(z) # rubocop:disable Metrics/MethodLength
      cmds = @cmds.clone
      stack = []
      altstack = []

      while cmds.any?
        cmd = cmds.shift
        if cmd.is_a? Integer
          unless execute_operation(cmd, cmds, stack, altstack, z)
            return false
          end
        else
          stack.append(cmd)
        end
      end

      return false if stack.empty? || stack.pop.empty?

      true
    end

    private

    def raw_serialize
      @cmds.map do |cmd|
        if cmd.is_a? Integer
          int_to_little_endian(cmd, 1)
        else
          serialized_element_prefix(cmd) + cmd
        end
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

    def execute_operation(cmd, cmds, stack, altstack, z)
      operation = op_code_function(cmd)

      case cmd
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

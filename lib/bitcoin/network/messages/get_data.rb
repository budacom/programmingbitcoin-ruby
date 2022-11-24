require_relative './base_message'

module Bitcoin
  module Network
    module Messages
      class GetData < BaseMessage
        TX_DATA_TYPE = 1
        BLOCK_DATA_TYPE = 2
        FILTERED_BLOCK_DATA_TYPE = 3
        COMPACT_BLOCK_DATA_TYPE = 4
        COMMAND = "getdata"

        def initialize
          @data = []
        end

        def add_data(data_type:, identifier:)
          @data << [data_type, identifier]
        end

        def serialize
          result = encode_varint(@data.length)
          @data.each do |data_type, identifier|
            result += int_to_little_endian(data_type, 4)
            result += identifier.reverse
          end
          result
        end
      end
    end
  end
end

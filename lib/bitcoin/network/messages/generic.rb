require_relative './base_message'

module Bitcoin
  module Network
    module Messages
      class Generic < BaseMessage
        def initialize(command, payload)
          @command = command
          @payload = payload
        end

        def command
          @command
        end

        def serialize
          @payload
        end
      end
    end
  end
end

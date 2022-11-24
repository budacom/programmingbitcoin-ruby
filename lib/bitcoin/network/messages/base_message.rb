# encoding: ascii-8bit
require_relative '../../../helpers/encoding_helper'

module Bitcoin
  module Network
    module Messages
      class BaseMessage
        include EncodingHelper

        def command
          self.class::COMMAND
        end
      end
    end
  end
end

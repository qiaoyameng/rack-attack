# frozen_string_literal: true

module Rack
  class Attack
    class Blocklist < Check
      def initialize(name = nil, options = {}, annotation_prefix: Check::DEFAULT_ANNOTATION_PREFIX, &block)
        super
        @type = :blocklist
      end
    end
  end
end
